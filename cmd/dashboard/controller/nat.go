package controller

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"

	dashboardRpc "github.com/nezhahq/nezha/cmd/dashboard/rpc"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

// List NAT Profiles
// @Summary List NAT profiles
// @Schemes
// @Description List NAT profiles
// @Security BearerAuth
// @Tags auth required
// @Param id query uint false "Resource ID"
// @Produce json
// @Success 200 {object} model.CommonResponse[[]model.NAT]
// @Router /nat [get]
func listNAT(c *gin.Context) ([]*model.NAT, error) {
	var n []*model.NAT

	slist := singleton.NATShared.GetSortedList()

	if err := copier.Copy(&n, &slist); err != nil {
		return nil, err
	}

	return n, nil
}

// Add NAT profile
// @Summary Add NAT profile
// @Security BearerAuth
// @Schemes
// @Description Add NAT profile
// @Tags auth required
// @Accept json
// @param request body model.NATForm true "NAT Request"
// @Produce json
// @Success 200 {object} model.CommonResponse[uint64]
// @Router /nat [post]
func createNAT(c *gin.Context) (uint64, error) {
	var nf model.NATForm
	var n model.NAT

	if err := c.ShouldBindJSON(&nf); err != nil {
		return 0, err
	}

	if nf.ServerID == 0 {
		return 0, singleton.Localizer.ErrorT("have invalid server id")
	}
	server, ok := singleton.ServerShared.Get(nf.ServerID)
	if !ok {
		return 0, singleton.Localizer.ErrorT("have invalid server id")
	}
	if !server.HasPermission(c) {
		return 0, singleton.Localizer.ErrorT("permission denied")
	}

	uid := getUid(c)

	n.UserID = uid
	n.Enabled = nf.Enabled
	n.Name = nf.Name
	n.Host = nf.Host
	n.Port = nf.Port
	n.ServerID = nf.ServerID

	if err := validateNATForm(nf, 0); err != nil {
		return 0, err
	}

	if err := singleton.DB.Create(&n).Error; err != nil {
		return 0, newGormError("%v", err)
	}

	if err := dashboardRpc.NATPortManagerShared.Upsert(&n); err != nil {
		_ = singleton.DB.Unscoped().Delete(&model.NAT{}, n.ID).Error
		return 0, fmt.Errorf("start nat listener: %w", err)
	}

	singleton.NATShared.Update(&n)
	return n.ID, nil
}

// Edit NAT profile
// @Summary Edit NAT profile
// @Security BearerAuth
// @Schemes
// @Description Edit NAT profile
// @Tags auth required
// @Accept json
// @param id path uint true "Profile ID"
// @param request body model.NATForm true "NAT Request"
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /nat/{id} [patch]
func updateNAT(c *gin.Context) (any, error) {
	idStr := c.Param("id")

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}

	var nf model.NATForm
	if err := c.ShouldBindJSON(&nf); err != nil {
		return nil, err
	}

	if nf.ServerID == 0 {
		return nil, singleton.Localizer.ErrorT("have invalid server id")
	}
	server, ok := singleton.ServerShared.Get(nf.ServerID)
	if !ok {
		return nil, singleton.Localizer.ErrorT("have invalid server id")
	}
	if !server.HasPermission(c) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	var n model.NAT
	if err = singleton.DB.First(&n, id).Error; err != nil {
		return nil, singleton.Localizer.ErrorT("profile id %d does not exist", id)
	}

	if !n.HasPermission(c) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	oldNAT := n
	n.Enabled = nf.Enabled
	n.Name = nf.Name
	n.Host = nf.Host
	n.Port = nf.Port
	n.ServerID = nf.ServerID

	if err := validateNATForm(nf, id); err != nil {
		return nil, err
	}

	if err := singleton.DB.Save(&n).Error; err != nil {
		return 0, newGormError("%v", err)
	}

	if err := dashboardRpc.NATPortManagerShared.Upsert(&n); err != nil {
		_ = singleton.DB.Save(&oldNAT).Error
		singleton.NATShared.Update(&oldNAT)
		_ = dashboardRpc.NATPortManagerShared.Upsert(&oldNAT)
		return nil, fmt.Errorf("start nat listener: %w", err)
	}

	singleton.NATShared.Update(&n)
	return nil, nil
}

// Batch delete NAT configurations
// @Summary Batch delete NAT configurations
// @Security BearerAuth
// @Schemes
// @Description Batch delete NAT configurations
// @Tags auth required
// @Accept json
// @param request body []uint64 true "id list"
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /batch-delete/nat [post]
func batchDeleteNAT(c *gin.Context) (any, error) {
	var n []uint64
	if err := c.ShouldBindJSON(&n); err != nil {
		return nil, err
	}

	var natConfigs []*model.NAT
	if err := singleton.DB.Find(&natConfigs, "id in (?)", n).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	for _, natConfig := range natConfigs {
		if !natConfig.HasPermission(c) {
			return nil, singleton.Localizer.ErrorT("permission denied")
		}
	}

	if err := singleton.DB.Unscoped().Delete(&model.NAT{}, "id in (?)", n).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	for id := range slices.Values(n) {
		dashboardRpc.NATPortManagerShared.Delete(id)
	}
	singleton.NATShared.Delete(n)
	return nil, nil
}

func validateNATForm(nf model.NATForm, currentID uint64) error {
	if nf.Port == 0 {
		return singleton.Localizer.ErrorT("invalid nat port")
	}
	if singleton.Conf != nil {
		if nf.Port == singleton.Conf.ListenPort {
			return singleton.Localizer.ErrorT("nat port conflicts with dashboard listen port")
		}
		if singleton.Conf.HTTPS.ListenPort != 0 && nf.Port == singleton.Conf.HTTPS.ListenPort {
			return singleton.Localizer.ErrorT("nat port conflicts with dashboard https listen port")
		}
	}
	if err := validateNATLocalService(nf.Host); err != nil {
		return err
	}
	if existing := singleton.NATShared.GetNATConfigByPort(nf.Port); existing != nil && existing.ID != currentID {
		return singleton.Localizer.ErrorT("nat port is already used")
	}
	return nil
}

func validateNATLocalService(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return singleton.Localizer.ErrorT("local service cannot be empty")
	}
	targetHost, targetPort, err := net.SplitHostPort(host)
	if err != nil {
		return singleton.Localizer.ErrorT("local service must be host:port")
	}
	if targetHost == "" {
		return singleton.Localizer.ErrorT("local service host cannot be empty")
	}
	port, err := strconv.ParseUint(targetPort, 10, 16)
	if err != nil || port == 0 {
		return singleton.Localizer.ErrorT("local service port is invalid")
	}
	return nil
}
