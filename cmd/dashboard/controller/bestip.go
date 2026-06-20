package controller

import (
	"context"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/bestip"
	"github.com/nezhahq/nezha/service/singleton"
)

var bestIPFissionRunner = func(ctx context.Context, userID uint64, form model.BestIPFissionForm) (*bestip.FissionRunResult, error) {
	return singleton.RunBestIPFission(ctx, userID, form, nil)
}

var bestIPFissionStreamRunner = func(ctx context.Context, userID uint64, form model.BestIPFissionForm, progress func(bestip.FissionProgressEvent)) (*bestip.FissionRunResult, error) {
	return singleton.RunBestIPFission(ctx, userID, form, progress)
}

// Run Best IP fission
// @Summary Run Best IP fission
// @Security BearerAuth
// @Schemes
// @Description Run Best IP fission from the provided seed IPs and scan config
// @Tags auth required
// @Accept json
// @Param request body model.BestIPFissionForm true "Best IP fission request"
// @Produce json
// @Success 200 {object} model.CommonResponse[model.BestIPFissionResult]
// @Router /bestip/fission [post]
func runBestIPFission(c *gin.Context) (*model.BestIPFissionResult, error) {
	var form model.BestIPFissionForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	result, err := bestIPFissionRunner(c.Request.Context(), getUid(c), form)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func streamBestIPFission(c *gin.Context) (any, error) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return nil, newWsError("%v", err)
	}
	defer conn.Close()

	var form model.BestIPFissionForm
	if err := conn.ReadJSON(&form); err != nil {
		return nil, newWsError("%v", err)
	}

	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	var writeMu sync.Mutex
	var writeErr error
	writeEvent := func(event bestip.FissionProgressEvent) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if writeErr != nil {
			return writeErr
		}
		if err := conn.WriteJSON(event); err != nil {
			writeErr = err
			cancel()
			return err
		}
		return nil
	}

	_, err = bestIPFissionStreamRunner(ctx, getUid(c), form, func(event bestip.FissionProgressEvent) {
		_ = writeEvent(event)
	})
	if err != nil {
		_ = writeEvent(bestip.FissionProgressEvent{Type: bestip.FissionProgressError, Error: err.Error()})
		return nil, newWsError("%v", err)
	}
	if writeErr != nil {
		return nil, newWsError("%v", writeErr)
	}
	return nil, newWsError("")
}

// Write Best IP DNS records
// @Summary Write Best IP DNS records
// @Security BearerAuth
// @Schemes
// @Description Write selected Best IP records to DDNS profiles
// @Tags auth required
// @Accept json
// @Param request body model.BestIPDNSWriteForm true "Best IP DNS write request"
// @Produce json
// @Success 200 {object} model.CommonResponse[[]model.BestIPDNSWriteResult]
// @Router /bestip/dns [post]
func writeBestIPDNS(c *gin.Context) ([]model.BestIPDNSWriteResult, error) {
	var form model.BestIPDNSWriteForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	return singleton.WriteBestIPDNS(c.Request.Context(), getUid(c), form)
}

// Get Best IP automation
// @Summary Get Best IP automation
// @Security BearerAuth
// @Schemes
// @Description Get current user's Best IP automation config
// @Tags auth required
// @Produce json
// @Success 200 {object} model.CommonResponse[model.BestIPAutomation]
// @Router /bestip/automation [get]
func getBestIPAutomation(c *gin.Context) (*model.BestIPAutomation, error) {
	automation, ok := singleton.BestIPAutomationShared.GetByUser(getUid(c))
	if !ok {
		return &model.BestIPAutomation{Common: model.Common{UserID: getUid(c)}, WriteTopN: 1}, nil
	}
	return automation, nil
}

// Save Best IP automation
// @Summary Save Best IP automation
// @Security BearerAuth
// @Schemes
// @Description Save current user's Best IP automation config
// @Tags auth required
// @Accept json
// @Param request body model.BestIPAutomationForm true "Best IP automation request"
// @Produce json
// @Success 200 {object} model.CommonResponse[model.BestIPAutomation]
// @Router /bestip/automation [post]
func saveBestIPAutomation(c *gin.Context) (*model.BestIPAutomation, error) {
	var form model.BestIPAutomationForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	if err := assertOwnsNotificationGroup(c, form.FissionNotificationGroupID); err != nil {
		return nil, err
	}
	if err := assertOwnsNotificationGroup(c, form.NotificationGroupID); err != nil {
		return nil, err
	}
	return singleton.BestIPAutomationShared.SaveForUser(getUid(c), form)
}

// Run Best IP automation
// @Summary Run Best IP automation
// @Security BearerAuth
// @Schemes
// @Description Manually run current user's Best IP automation
// @Tags auth required
// @Produce json
// @Success 200 {object} model.CommonResponse[model.BestIPAutomationHistory]
// @Router /bestip/automation/run [post]
func runBestIPAutomation(c *gin.Context) (*model.BestIPAutomationHistory, error) {
	return singleton.BestIPAutomationShared.RunForUser(c.Request.Context(), getUid(c))
}

// Rollback Best IP automation
// @Summary Rollback Best IP automation
// @Security BearerAuth
// @Schemes
// @Description Roll back current user's Best IP DNS records to the stored rollback point
// @Tags auth required
// @Produce json
// @Success 200 {object} model.CommonResponse[model.BestIPAutomationHistory]
// @Router /bestip/automation/rollback [post]
func rollbackBestIPAutomation(c *gin.Context) (*model.BestIPAutomationHistory, error) {
	return singleton.BestIPAutomationShared.RollbackForUser(c.Request.Context(), getUid(c))
}

// List Best IP automation histories
// @Summary List Best IP automation histories
// @Security BearerAuth
// @Schemes
// @Description List current user's recent Best IP automation histories
// @Tags auth required
// @Produce json
// @Success 200 {object} model.CommonResponse[[]model.BestIPAutomationHistory]
// @Router /bestip/automation/history [get]
func listBestIPAutomationHistory(c *gin.Context) ([]*model.BestIPAutomationHistory, error) {
	return singleton.BestIPAutomationShared.HistoriesForUser(getUid(c), 20)
}

// Notify Best IP result
// @Summary Notify Best IP result
// @Security BearerAuth
// @Schemes
// @Description Send selected Best IP records to a notification group
// @Tags auth required
// @Accept json
// @Param request body model.BestIPNotifyForm true "Best IP notify request"
// @Produce json
// @Success 200 {object} model.CommonResponse[model.BestIPNotifyResult]
// @Router /bestip/notify [post]
func notifyBestIPResult(c *gin.Context) (*model.BestIPNotifyResult, error) {
	var form model.BestIPNotifyForm
	if err := c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}
	if err := assertOwnsNotificationGroup(c, form.NotificationGroupID); err != nil {
		return nil, err
	}
	return singleton.SendBestIPNotification(getUid(c), form)
}
