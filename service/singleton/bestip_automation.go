package singleton

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	ddns2 "github.com/nezhahq/nezha/pkg/ddns"
	"github.com/nezhahq/nezha/pkg/ddns/webhook"
	"github.com/nezhahq/nezha/pkg/utils"
)

type BestIPAutomationClass struct {
	class[uint64, *model.BestIPAutomation]
	runMu sync.Mutex
}

type BestIPDNSWriteRequest struct {
	UserID       uint64
	DDNSProfiles []uint64
	Domains      []string
	IPv4         string
	IPv6         string
	IPv4Records  []string
	IPv6Records  []string
}

var BestIPAutomationFissionRunner = func(ctx context.Context, config bestip.FissionConfig) (*bestip.FissionRunResult, error) {
	return bestip.NewFissionService(config).Run(ctx)
}

var BestIPNotificationSender = func(groupID uint64, message string, muteLabel string) {
	if groupID == 0 || NotificationShared == nil {
		return
	}
	NotificationShared.SendNotification(groupID, message, muteLabel)
}

func NewBestIPAutomationClass() *BestIPAutomationClass {
	c := &BestIPAutomationClass{
		class: class[uint64, *model.BestIPAutomation]{
			list: make(map[uint64]*model.BestIPAutomation),
		},
	}

	var sortedList []*model.BestIPAutomation
	DB.Find(&sortedList)
	for _, automation := range sortedList {
		if err := c.register(automation); err != nil {
			log.Printf("NEZHA>> BestIP automation %d failed to register: %v", automation.ID, err)
		}
		c.list[automation.ID] = automation
	}
	c.sortList()
	return c
}

func (c *BestIPAutomationClass) GetByUser(userID uint64) (*model.BestIPAutomation, bool) {
	c.listMu.RLock()
	defer c.listMu.RUnlock()
	for _, automation := range c.list {
		if automation.GetUserID() == userID {
			return automation, true
		}
	}
	return nil, false
}

func (c *BestIPAutomationClass) SaveForUser(userID uint64, form model.BestIPAutomationForm) (*model.BestIPAutomation, error) {
	if form.Enabled && strings.TrimSpace(form.Scheduler) == "" {
		return nil, Localizer.ErrorT("cron expression is required")
	}
	if strings.TrimSpace(form.Scheduler) != "" {
		if err := validateBestIPAutomationScheduler(form.Scheduler); err != nil {
			return nil, err
		}
	}
	if !canUseBestIPDDNSProfiles(userID, form.DDNSProfiles) {
		return nil, Localizer.ErrorT("permission denied")
	}
	if err := canUseBestIPNotificationGroup(userID, form.NotificationGroupID); err != nil {
		return nil, err
	}
	config, err := bestip.NormalizeFissionConfig(form.Fission)
	if err != nil {
		return nil, err
	}

	automation, ok := c.GetByUser(userID)
	if !ok {
		automation = &model.BestIPAutomation{Common: model.Common{UserID: userID}}
	}
	automation.Enabled = form.Enabled
	automation.Scheduler = strings.TrimSpace(form.Scheduler)
	automation.AutoWriteDNS = form.AutoWriteDNS
	automation.PushSuccessful = form.PushSuccessful
	automation.PushFailed = form.PushFailed
	automation.NotificationGroupID = form.NotificationGroupID
	automation.WriteTopN = clampBestIPWriteTopN(form.WriteTopN)
	automation.DDNSProfiles = normalizeUintList(form.DDNSProfiles)
	automation.Domains = normalizeStringList(form.Domains)
	automation.Fission = config

	if automation.ID == 0 {
		if err := DB.Create(automation).Error; err != nil {
			return nil, err
		}
	} else if err := DB.Save(automation).Error; err != nil {
		return nil, err
	}
	if err := c.Update(automation); err != nil {
		return nil, err
	}
	return automation, nil
}

func (c *BestIPAutomationClass) Update(automation *model.BestIPAutomation) error {
	c.listMu.Lock()
	old := c.list[automation.ID]
	if old != nil && old.CronJobID != 0 && CronShared != nil {
		CronShared.Remove(cron.EntryID(old.CronJobID))
	}

	automation.CronJobID = 0
	if err := c.register(automation); err != nil {
		c.listMu.Unlock()
		return err
	}
	c.list[automation.ID] = automation
	c.listMu.Unlock()

	c.sortList()
	return nil
}

func (c *BestIPAutomationClass) Delete(idList []uint64) {
	c.listMu.Lock()
	for _, id := range idList {
		automation := c.list[id]
		if automation != nil && automation.CronJobID != 0 && CronShared != nil {
			CronShared.Remove(cron.EntryID(automation.CronJobID))
		}
		delete(c.list, id)
	}
	c.listMu.Unlock()
	c.sortList()
}

func (c *BestIPAutomationClass) RunForUser(ctx context.Context, userID uint64) (*model.BestIPAutomationHistory, error) {
	automation, ok := c.GetByUser(userID)
	if !ok {
		return nil, Localizer.ErrorT("bestip automation is not configured")
	}
	return c.RunByID(ctx, automation.ID)
}

func (c *BestIPAutomationClass) RunByID(ctx context.Context, id uint64) (*model.BestIPAutomationHistory, error) {
	c.runMu.Lock()
	defer c.runMu.Unlock()

	automation, ok := c.Get(id)
	if !ok {
		return nil, Localizer.ErrorT("bestip automation is not configured")
	}
	return c.run(ctx, automation)
}

func (c *BestIPAutomationClass) RollbackForUser(ctx context.Context, userID uint64) (*model.BestIPAutomationHistory, error) {
	automation, ok := c.GetByUser(userID)
	if !ok {
		return nil, Localizer.ErrorT("bestip automation is not configured")
	}
	return c.RollbackByID(ctx, automation.ID)
}

func (c *BestIPAutomationClass) RollbackByID(ctx context.Context, id uint64) (*model.BestIPAutomationHistory, error) {
	c.runMu.Lock()
	defer c.runMu.Unlock()

	automation, ok := c.Get(id)
	if !ok {
		return nil, Localizer.ErrorT("bestip automation is not configured")
	}
	if len(automation.RollbackIPv4Records) == 0 && len(automation.RollbackIPv6Records) == 0 {
		return nil, Localizer.ErrorT("no rollback records available")
	}

	startedAt := time.Now()
	currentIPv4 := slices.Clone(automation.LastIPv4Records)
	currentIPv6 := slices.Clone(automation.LastIPv6Records)
	targetIPv4 := slices.Clone(automation.RollbackIPv4Records)
	targetIPv6 := slices.Clone(automation.RollbackIPv6Records)
	history := &model.BestIPAutomationHistory{
		Common:              model.Common{UserID: automation.GetUserID()},
		AutomationID:        automation.ID,
		Action:              model.BestIPAutomationActionRollback,
		StartedAt:           startedAt,
		IPv4Records:         targetIPv4,
		IPv6Records:         targetIPv6,
		RollbackIPv4Records: currentIPv4,
		RollbackIPv6Records: currentIPv6,
	}

	results, err := WriteBestIPDNS(ctx, automation.GetUserID(), model.BestIPDNSWriteForm{
		DDNSProfiles: automation.DDNSProfiles,
		Domains:      automation.Domains,
		IPv4Records:  targetIPv4,
		IPv6Records:  targetIPv6,
	})
	history.DNSResults = results
	automation.LastDNSResults = results
	if err != nil {
		return c.finishAutomationFailure(automation, history, err)
	}
	if err := firstBestIPDNSWriteError(results); err != nil {
		return c.finishAutomationFailure(automation, history, err)
	}

	automation.LastIPv4Records = targetIPv4
	automation.LastIPv6Records = targetIPv6
	automation.RollbackIPv4Records = currentIPv4
	automation.RollbackIPv6Records = currentIPv6
	return c.finishAutomationSuccess(automation, history)
}

func (c *BestIPAutomationClass) HistoriesForUser(userID uint64, limit int) ([]*model.BestIPAutomationHistory, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var histories []*model.BestIPAutomationHistory
	err := DB.Where("user_id = ?", userID).Order("id DESC").Limit(limit).Find(&histories).Error
	return histories, err
}

func (c *BestIPAutomationClass) register(automation *model.BestIPAutomation) error {
	if !automation.Enabled {
		return nil
	}
	if CronShared == nil {
		return fmt.Errorf("cron scheduler is not initialized")
	}
	jobID, err := CronShared.AddFunc(automation.Scheduler, func() {
		if _, err := c.RunByID(context.Background(), automation.ID); err != nil {
			log.Printf("NEZHA>> BestIP automation %d failed: %v", automation.ID, err)
		}
	})
	if err != nil {
		return err
	}
	automation.CronJobID = uint64(jobID)
	return nil
}

func (c *BestIPAutomationClass) run(ctx context.Context, automation *model.BestIPAutomation) (*model.BestIPAutomationHistory, error) {
	history := &model.BestIPAutomationHistory{
		Common:       model.Common{UserID: automation.GetUserID()},
		AutomationID: automation.ID,
		Action:       model.BestIPAutomationActionRun,
		StartedAt:    time.Now(),
	}

	result, err := BestIPAutomationFissionRunner(ctx, automation.Fission)
	if err != nil {
		return c.finishAutomationFailure(automation, history, err)
	}
	history.Candidates = result.Candidates
	automation.LastCandidates = result.Candidates

	if automation.AutoWriteDNS {
		ipv4Records, ipv6Records := bestIPRecordsFromCandidates(result.Candidates, automation.WriteTopN)
		if len(ipv4Records) == 0 && len(ipv6Records) == 0 {
			return c.finishAutomationFailure(automation, history, Localizer.ErrorT("no candidate records available"))
		}

		history.IPv4Records = ipv4Records
		history.IPv6Records = ipv6Records
		history.RollbackIPv4Records = slices.Clone(automation.LastIPv4Records)
		history.RollbackIPv6Records = slices.Clone(automation.LastIPv6Records)

		results, err := WriteBestIPDNS(ctx, automation.GetUserID(), model.BestIPDNSWriteForm{
			DDNSProfiles: automation.DDNSProfiles,
			Domains:      automation.Domains,
			IPv4Records:  ipv4Records,
			IPv6Records:  ipv6Records,
		})
		history.DNSResults = results
		automation.LastDNSResults = results
		if err != nil {
			return c.finishAutomationFailure(automation, history, err)
		}
		if err := firstBestIPDNSWriteError(results); err != nil {
			return c.finishAutomationFailure(automation, history, err)
		}

		automation.RollbackIPv4Records = history.RollbackIPv4Records
		automation.RollbackIPv6Records = history.RollbackIPv6Records
		automation.LastIPv4Records = ipv4Records
		automation.LastIPv6Records = ipv6Records
	}

	return c.finishAutomationSuccess(automation, history)
}

func (c *BestIPAutomationClass) finishAutomationSuccess(automation *model.BestIPAutomation, history *model.BestIPAutomationHistory) (*model.BestIPAutomationHistory, error) {
	now := time.Now()
	history.FinishedAt = now
	history.Success = true
	automation.LastRunAt = now
	automation.LastResult = true
	automation.LastError = ""
	if err := DB.Save(automation).Error; err != nil {
		return nil, err
	}
	if err := DB.Create(history).Error; err != nil {
		return nil, err
	}
	c.notifyAutomationSuccess(automation, history)
	return history, nil
}

func (c *BestIPAutomationClass) finishAutomationFailure(automation *model.BestIPAutomation, history *model.BestIPAutomationHistory, err error) (*model.BestIPAutomationHistory, error) {
	now := time.Now()
	history.FinishedAt = now
	history.Success = false
	history.Error = err.Error()
	automation.LastRunAt = now
	automation.LastResult = false
	automation.LastError = err.Error()
	if saveErr := DB.Save(automation).Error; saveErr != nil {
		return nil, saveErr
	}
	if saveErr := DB.Create(history).Error; saveErr != nil {
		return nil, saveErr
	}
	c.notifyAutomationFailure(automation, history, err)
	return history, err
}

func (c *BestIPAutomationClass) notifyAutomationSuccess(automation *model.BestIPAutomation, history *model.BestIPAutomationHistory) {
	if !automation.PushSuccessful || automation.NotificationGroupID == 0 {
		return
	}
	ipv4Records, ipv6Records := bestIPNotificationRecords(automation, history)
	message := formatBestIPNotificationMessage(bestIPNotificationMessage{
		Title:               bestIPAutomationSuccessTitle(history.Action),
		IPv4Records:         ipv4Records,
		IPv6Records:         ipv6Records,
		Domains:             automation.Domains,
		DNSResults:          history.DNSResults,
		CandidateCount:      len(history.Candidates),
		SelectedRecordCount: len(ipv4Records) + len(ipv6Records),
		CandidateDetails:    bestIPTopCandidateDetails(history.Candidates),
	})
	BestIPNotificationSender(automation.NotificationGroupID, message, "")
	if NotificationShared != nil {
		NotificationShared.UnMuteNotification(automation.NotificationGroupID, NotificationMuteLabel.BestIPAutomationFailure(automation.ID))
	}
}

func (c *BestIPAutomationClass) notifyAutomationFailure(automation *model.BestIPAutomation, history *model.BestIPAutomationHistory, err error) {
	if !automation.PushFailed || automation.NotificationGroupID == 0 {
		return
	}
	message := formatBestIPNotificationMessage(bestIPNotificationMessage{
		Title:          bestIPAutomationFailureTitle(history.Action),
		Domains:        automation.Domains,
		DNSResults:     history.DNSResults,
		CandidateCount: len(history.Candidates),
		Error:          err,
	})
	BestIPNotificationSender(automation.NotificationGroupID, message, NotificationMuteLabel.BestIPAutomationFailure(automation.ID))
}

type bestIPNotificationMessage struct {
	Title               string
	IPv4Records         []string
	IPv6Records         []string
	Domains             []string
	DNSResults          []model.BestIPDNSWriteResult
	CandidateCount      int
	SelectedRecordCount int
	CandidateDetails    []bestip.CandidateResult
	Error               error
}

func bestIPNotificationRecords(automation *model.BestIPAutomation, history *model.BestIPAutomationHistory) ([]string, []string) {
	ipv4Records := slices.Clone(history.IPv4Records)
	ipv6Records := slices.Clone(history.IPv6Records)
	if len(ipv4Records) > 0 || len(ipv6Records) > 0 {
		return ipv4Records, ipv6Records
	}
	return bestIPRecordsFromCandidates(automation.LastCandidates, automation.WriteTopN)
}

func bestIPAutomationSuccessTitle(action string) string {
	if action == model.BestIPAutomationActionRollback {
		return Localizer.T("[Best IP] Rollback completed")
	}
	return Localizer.T("[Best IP] Automation completed")
}

func bestIPAutomationFailureTitle(action string) string {
	if action == model.BestIPAutomationActionRollback {
		return Localizer.T("[Best IP] Rollback failed")
	}
	return Localizer.T("[Best IP] Automation failed")
}

func formatBestIPNotificationMessage(message bestIPNotificationMessage) string {
	lines := []string{
		message.Title,
		Localizer.Tf("IPv4: %s", bestIPNotificationList(message.IPv4Records)),
		Localizer.Tf("IPv6: %s", bestIPNotificationList(message.IPv6Records)),
	}
	if len(message.Domains) > 0 {
		lines = append(lines, Localizer.Tf("Domains: %s", strings.Join(message.Domains, ", ")))
	}
	if len(message.DNSResults) > 0 {
		lines = append(lines, Localizer.Tf("DNS writeback: %s", bestIPDNSNotificationStatus(message.DNSResults)))
	}
	if message.CandidateCount > 0 {
		lines = append(lines, Localizer.Tf("Candidates: %d", message.CandidateCount))
	}
	if message.SelectedRecordCount > 0 {
		lines = append(lines, Localizer.Tf("Selected records: %d", message.SelectedRecordCount))
	}
	if len(message.CandidateDetails) > 0 {
		lines = append(lines, Localizer.T("Candidate details: IP · latency · success · download · score"))
		for index, candidate := range message.CandidateDetails {
			lines = append(lines, fmt.Sprintf(
				"%d. %s · %s · %s · %s · %.3f",
				index+1,
				candidate.IP,
				formatBestIPNotificationLatency(candidate.AvgLatencyMS),
				formatBestIPNotificationSuccessRate(candidate.SuccessRate),
				formatBestIPNotificationDownload(candidate.DownloadMBps),
				candidate.Score,
			))
		}
	}
	if message.Error != nil {
		lines = append(lines, Localizer.Tf("Error: %s", message.Error.Error()))
	}
	lines = append(lines, Localizer.Tf("Time: %s", bestIPNotificationTime().Format("2006-01-02 15:04:05")))
	return strings.Join(lines, "\n")
}

func bestIPNotificationList(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ", ")
}

func bestIPDNSNotificationStatus(results []model.BestIPDNSWriteResult) string {
	for _, result := range results {
		if !result.Success {
			if result.Error != "" {
				return Localizer.Tf("failed: %s", result.Error)
			}
			return Localizer.T("failed")
		}
	}
	return Localizer.T("success")
}

func formatBestIPNotificationLatency(value float64) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f ms", value)
}

func formatBestIPNotificationSuccessRate(value float64) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", value*100)
}

func formatBestIPNotificationDownload(value float64) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f MB/s", value)
}

func bestIPNotificationTime() time.Time {
	loc := Loc
	if loc == nil {
		loc = time.Local
	}
	return time.Now().In(loc)
}

func SendBestIPNotification(userID uint64, form model.BestIPNotifyForm) (*model.BestIPNotifyResult, error) {
	if form.NotificationGroupID == 0 {
		return nil, Localizer.ErrorT("notification group id is required")
	}
	if err := canUseBestIPNotificationGroup(userID, form.NotificationGroupID); err != nil {
		return nil, err
	}

	ipv4Records, ipv6Records, err := normalizeBestIPNotifyRecords(form)
	if err != nil {
		return nil, err
	}
	if len(ipv4Records) == 0 && len(ipv6Records) == 0 {
		return nil, Localizer.ErrorT("at least one IP address is required")
	}

	message := formatBestIPNotificationMessage(bestIPNotificationMessage{
		Title:               Localizer.T("[Best IP] Selected records"),
		IPv4Records:         ipv4Records,
		IPv6Records:         ipv6Records,
		Domains:             normalizeStringList(form.Domains),
		CandidateCount:      len(form.Candidates),
		SelectedRecordCount: len(ipv4Records) + len(ipv6Records),
		CandidateDetails:    bestIPTopCandidateDetails(form.Candidates),
	})
	BestIPNotificationSender(form.NotificationGroupID, message, "")
	return &model.BestIPNotifyResult{Success: true, IPv4: ipv4Records, IPv6: ipv6Records}, nil
}

func validateBestIPAutomationScheduler(scheduler string) error {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	_, err := parser.Parse(scheduler)
	return err
}

func WriteBestIPDNS(ctx context.Context, userID uint64, form model.BestIPDNSWriteForm) ([]model.BestIPDNSWriteResult, error) {
	if len(form.DDNSProfiles) == 0 {
		return nil, Localizer.ErrorT("DDNS profile id is required")
	}
	ipRecords := normalizeBestIPDNSRecords(form)
	if len(ipRecords.IPv4Addrs) == 0 && len(ipRecords.IPv6Addrs) == 0 {
		return nil, Localizer.ErrorT("at least one IP address is required")
	}
	if !canUseBestIPDDNSProfiles(userID, form.DDNSProfiles) {
		return nil, Localizer.ErrorT("permission denied")
	}

	ctx = withBestIPDNSServers(ctx)
	ip := &model.IP{IPv4Addr: firstBestIPRecord(ipRecords.IPv4Addrs), IPv6Addr: firstBestIPRecord(ipRecords.IPv6Addrs)}
	providers, err := DDNSShared.GetDDNSProvidersFromProfiles(form.DDNSProfiles, ip)
	if err != nil {
		return nil, err
	}

	results := make([]model.BestIPDNSWriteResult, 0, len(providers))
	for _, provider := range providers {
		provider.IPRecords = ipRecords
		applyBestIPDNSRecordFamilies(provider, ipRecords)
		domainResults := provider.UpdateDomain(ctx, form.Domains...)
		item := model.BestIPDNSWriteResult{
			ProfileID: provider.GetProfileID(),
			Provider:  provider.DDNSProfile.Provider,
			Domains:   domainsFromBestIPDNSResults(domainResults),
			Success:   true,
		}
		for _, domainResult := range domainResults {
			if !domainResult.Success {
				item.Success = false
				item.Error = domainResult.Error
				break
			}
		}
		results = append(results, item)
	}
	return results, nil
}

func normalizeBestIPDNSRecords(form model.BestIPDNSWriteForm) *ddns2.IPRecords {
	return &ddns2.IPRecords{
		IPv4Addrs: normalizeBestIPRecordList(form.IPv4Records, form.IPv4),
		IPv6Addrs: normalizeBestIPRecordList(form.IPv6Records, form.IPv6),
	}
}

func normalizeBestIPRecordList(records []string, fallback string) []string {
	source := records
	if len(source) == 0 && strings.TrimSpace(fallback) != "" {
		source = []string{fallback}
	}
	return normalizeStringList(source)
}

func applyBestIPDNSRecordFamilies(provider *ddns2.Provider, ipRecords *ddns2.IPRecords) {
	profile := *provider.DDNSProfile
	enableIPv4 := profile.EnableIPv4 != nil && *profile.EnableIPv4 && len(ipRecords.IPv4Addrs) > 0
	enableIPv6 := profile.EnableIPv6 != nil && *profile.EnableIPv6 && len(ipRecords.IPv6Addrs) > 0
	profile.EnableIPv4 = &enableIPv4
	profile.EnableIPv6 = &enableIPv6
	provider.DDNSProfile = &profile

	if setter, ok := provider.Setter.(*webhook.Provider); ok {
		setter.DDNSProfile = &profile
	}
}

func domainsFromBestIPDNSResults(results []ddns2.UpdateDomainResult) []string {
	out := make([]string, 0, len(results))
	for _, result := range results {
		out = append(out, result.Domain)
	}
	return out
}

func withBestIPDNSServers(ctx context.Context) context.Context {
	servers := utils.DNSServers
	if Conf != nil {
		confServers := normalizeStringList(strings.Split(Conf.DNSServers, ","))
		if len(confServers) > 0 {
			servers = confServers
		}
	}
	return context.WithValue(ctx, ddns2.DNSServerKey{}, servers)
}

func canUseBestIPDDNSProfiles(userID uint64, profileIDs []uint64) bool {
	for _, id := range profileIDs {
		profile, ok := DDNSShared.Get(id)
		if !ok {
			return false
		}
		if profile.GetUserID() != userID && !userIsAdmin(userID) {
			return false
		}
	}
	return true
}

func canUseBestIPNotificationGroup(userID uint64, groupID uint64) error {
	if groupID == 0 {
		return nil
	}
	var group model.NotificationGroup
	if err := DB.First(&group, groupID).Error; err != nil {
		return Localizer.ErrorT("notification group id %d does not exist", groupID)
	}
	if group.GetUserID() != userID && !userIsAdmin(userID) {
		return Localizer.ErrorT("permission denied")
	}
	return nil
}

func normalizeBestIPNotifyRecords(form model.BestIPNotifyForm) ([]string, []string, error) {
	ipv4Raw := normalizeBestIPRecordList(form.IPv4Records, form.IPv4)
	ipv6Raw := normalizeBestIPRecordList(form.IPv6Records, form.IPv6)
	if len(ipv4Raw) == 0 && len(ipv6Raw) == 0 && len(form.Candidates) > 0 {
		ipv4Raw, ipv6Raw = bestIPRecordsFromCandidates(form.Candidates, form.WriteTopN)
	}

	ipv4Records, err := normalizeBestIPNotifyRecordFamily(ipv4Raw, false)
	if err != nil {
		return nil, nil, err
	}
	ipv6Records, err := normalizeBestIPNotifyRecordFamily(ipv6Raw, true)
	if err != nil {
		return nil, nil, err
	}
	return ipv4Records, ipv6Records, nil
}

func normalizeBestIPNotifyRecordFamily(values []string, wantIPv6 bool) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", value, err)
		}
		if wantIPv6 && !addr.Is6() {
			return nil, fmt.Errorf("invalid IPv6 address %q", value)
		}
		if !wantIPv6 && !addr.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address %q", value)
		}
		ip := addr.String()
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out, nil
}

func bestIPRecordsFromCandidates(candidates []bestip.CandidateResult, topN int) ([]string, []string) {
	topN = clampBestIPWriteTopN(topN)
	ipv4Records := make([]string, 0, topN)
	ipv6Records := make([]string, 0, topN)
	seen := make(map[string]struct{}, topN)
	for _, candidate := range candidates {
		if len(ipv4Records)+len(ipv6Records) >= topN {
			break
		}
		ip := strings.TrimSpace(candidate.IP)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		switch bestIPCandidateFamily(candidate) {
		case "ipv4":
			ipv4Records = append(ipv4Records, ip)
			seen[ip] = struct{}{}
		case "ipv6":
			ipv6Records = append(ipv6Records, ip)
			seen[ip] = struct{}{}
		}
	}
	return ipv4Records, ipv6Records
}

func bestIPCandidateFamily(candidate bestip.CandidateResult) string {
	family := strings.ToLower(strings.TrimSpace(candidate.Family))
	if family == "ipv4" || family == "ipv6" {
		return family
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(candidate.IP))
	if err != nil {
		return ""
	}
	if addr.Is6() {
		return "ipv6"
	}
	if addr.Is4() {
		return "ipv4"
	}
	return ""
}

func bestIPTopCandidateDetails(candidates []bestip.CandidateResult) []bestip.CandidateResult {
	const limit = 10
	out := make([]bestip.CandidateResult, 0, min(len(candidates), limit))
	seen := make(map[string]struct{}, limit)
	for _, candidate := range candidates {
		ip := strings.TrimSpace(candidate.IP)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, candidate)
		if len(out) == limit {
			break
		}
	}
	return out
}

func firstBestIPDNSWriteError(results []model.BestIPDNSWriteResult) error {
	for _, result := range results {
		if !result.Success {
			if result.Error != "" {
				return fmt.Errorf("%s", result.Error)
			}
			return fmt.Errorf("DNS writeback failed")
		}
	}
	return nil
}

func normalizeUintList(values []uint64) []uint64 {
	out := make([]uint64, 0, len(values))
	seen := make(map[uint64]struct{}, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func firstBestIPRecord(records []string) string {
	if len(records) == 0 {
		return ""
	}
	return records[0]
}

func clampBestIPWriteTopN(value int) int {
	if value <= 0 {
		return 1
	}
	if value > 20 {
		return 20
	}
	return value
}

func (c *BestIPAutomationClass) sortList() {
	c.listMu.RLock()
	defer c.listMu.RUnlock()

	sortedList := utils.MapValuesToSlice(c.list)
	slices.SortFunc(sortedList, func(a, b *model.BestIPAutomation) int {
		return int(a.ID) - int(b.ID)
	})

	c.sortedListMu.Lock()
	defer c.sortedListMu.Unlock()
	c.sortedList = sortedList
}
