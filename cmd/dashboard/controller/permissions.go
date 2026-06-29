package controller

import (
	"iter"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

func callerIsAdmin(c *gin.Context) bool {
	auth, ok := c.Get(model.CtxKeyAuthorizedUser)
	if !ok {
		return false
	}
	user, ok := auth.(*model.User)
	if !ok || user == nil {
		return false
	}
	return user.Role.IsAdmin()
}

func userFeatureMiddleware(feature model.UserFeature) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth, ok := c.Get(model.CtxKeyAuthorizedUser)
		if !ok {
			c.JSON(http.StatusOK, newErrorResponse(singleton.Localizer.ErrorT("unauthorized")))
			c.Abort()
			return
		}
		user, ok := auth.(*model.User)
		if !ok || user == nil || !user.HasFeature(feature) {
			c.JSON(http.StatusOK, newErrorResponse(singleton.Localizer.ErrorT("permission denied")))
			c.Abort()
			return
		}
		c.Next()
	}
}

func userCanViewServer(c *gin.Context, server *model.Server) bool {
	if server == nil {
		return false
	}
	if callerIsAdmin(c) {
		return true
	}
	if _, isMember := c.Get(model.CtxKeyAuthorizedUser); isMember {
		if server.HasPermission(c) {
			return true
		}
		return !server.HideForGuest
	}
	return !server.HideForGuest
}

func userCanViewService(c *gin.Context, service *model.Service) bool {
	if service == nil {
		return false
	}
	if service.EnableShowInService {
		return true
	}
	if callerIsAdmin(c) {
		return true
	}
	if _, isMember := c.Get(model.CtxKeyAuthorizedUser); isMember {
		return service.HasPermission(c)
	}
	return false
}

func assertOwnsNotificationGroup(c *gin.Context, groupID uint64) error {
	if groupID == 0 {
		return nil
	}

	var ng model.NotificationGroup
	if err := singleton.DB.First(&ng, groupID).Error; err != nil {
		return singleton.Localizer.ErrorT("notification group id %d does not exist", groupID)
	}
	if !ng.HasPermission(c) {
		return singleton.Localizer.ErrorT("permission denied")
	}
	return nil
}

func assertOwnsServers(c *gin.Context, ids iter.Seq[uint64]) error {
	for id := range ids {
		server, ok := singleton.ServerShared.Get(id)
		if !ok || server == nil {
			return singleton.Localizer.ErrorT("server id %d does not exist", id)
		}
		if !server.HasPermission(c) {
			return singleton.Localizer.ErrorT("permission denied")
		}
	}
	return nil
}

func assertOwnsCrons(c *gin.Context, ids iter.Seq[uint64]) error {
	for id := range ids {
		cron, ok := singleton.CronShared.Get(id)
		if !ok || cron == nil {
			return singleton.Localizer.ErrorT("task id %d does not exist", id)
		}
		if !cron.HasPermission(c) {
			return singleton.Localizer.ErrorT("permission denied")
		}
	}
	return nil
}

func assertOwnsDDNSProfiles(c *gin.Context, ids iter.Seq[uint64]) error {
	for id := range ids {
		profile, ok := singleton.DDNSShared.Get(id)
		if !ok || profile == nil {
			return singleton.Localizer.ErrorT("ddns id %d does not exist", id)
		}
		if !profile.HasPermission(c) {
			return singleton.Localizer.ErrorT("permission denied")
		}
	}
	return nil
}

func assertOwnsNotifications(c *gin.Context, ids iter.Seq[uint64]) error {
	for id := range ids {
		notification, ok := singleton.NotificationShared.Get(id)
		if !ok || notification == nil {
			return singleton.Localizer.ErrorT("notification id %d does not exist", id)
		}
		if !notification.HasPermission(c) {
			return singleton.Localizer.ErrorT("permission denied")
		}
	}
	return nil
}
