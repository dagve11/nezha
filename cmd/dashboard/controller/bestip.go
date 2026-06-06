package controller

import (
	"context"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	"github.com/nezhahq/nezha/pkg/ddns"
	"github.com/nezhahq/nezha/pkg/ddns/webhook"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/service/singleton"
)

var bestIPFissionRunner = func(ctx context.Context, config bestip.FissionConfig) (*bestip.FissionRunResult, error) {
	return bestip.NewFissionService(config).Run(ctx)
}

func runBestIPFission(c *gin.Context) (*model.BestIPFissionResult, error) {
	var form model.BestIPFissionForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	result, err := bestIPFissionRunner(c.Request.Context(), form)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func writeBestIPDNS(c *gin.Context) ([]model.BestIPDNSWriteResult, error) {
	var form model.BestIPDNSWriteForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	if len(form.DDNSProfiles) == 0 {
		return nil, singleton.Localizer.ErrorT("DDNS profile id is required")
	}
	ipRecords := normalizeBestIPDNSRecords(form)
	if len(ipRecords.IPv4Addrs) == 0 && len(ipRecords.IPv6Addrs) == 0 {
		return nil, singleton.Localizer.ErrorT("at least one IP address is required")
	}
	if !singleton.DDNSShared.CheckPermission(c, slices.Values(form.DDNSProfiles)) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	confServers := strings.Split(singleton.Conf.DNSServers, ",")
	ctx := context.WithValue(c.Request.Context(), ddns.DNSServerKey{}, utils.IfOr(confServers[0] != "", confServers, utils.DNSServers))
	ip := &model.IP{IPv4Addr: firstRecord(ipRecords.IPv4Addrs), IPv6Addr: firstRecord(ipRecords.IPv6Addrs)}
	providers, err := singleton.DDNSShared.GetDDNSProvidersFromProfiles(form.DDNSProfiles, ip)
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
			Domains:   domainsFromDDNSResults(domainResults),
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

func applyBestIPDNSRecordFamilies(provider *ddns.Provider, ipRecords *ddns.IPRecords) {
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

func normalizeBestIPDNSRecords(form model.BestIPDNSWriteForm) *ddns.IPRecords {
	return &ddns.IPRecords{
		IPv4Addrs: normalizeBestIPRecordList(form.IPv4Records, form.IPv4),
		IPv6Addrs: normalizeBestIPRecordList(form.IPv6Records, form.IPv6),
	}
}

func normalizeBestIPRecordList(records []string, fallback string) []string {
	source := records
	if len(source) == 0 && strings.TrimSpace(fallback) != "" {
		source = []string{fallback}
	}

	out := make([]string, 0, len(source))
	seen := make(map[string]struct{}, len(source))
	for _, record := range source {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}
		if _, ok := seen[record]; ok {
			continue
		}
		seen[record] = struct{}{}
		out = append(out, record)
	}
	return out
}

func firstRecord(records []string) string {
	if len(records) == 0 {
		return ""
	}
	return records[0]
}

func domainsFromDDNSResults(results []ddns.UpdateDomainResult) []string {
	out := make([]string, 0, len(results))
	for _, result := range results {
		out = append(out, result.Domain)
	}
	return out
}
