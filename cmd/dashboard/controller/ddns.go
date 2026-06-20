package controller

import (
	"slices"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
	"golang.org/x/net/idna"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

// List DDNS Profiles
// @Summary List DDNS profiles
// @Schemes
// @Description List DDNS profiles
// @Security BearerAuth
// @Tags auth required
// @Param id query uint false "Resource ID"
// @Produce json
// @Success 200 {object} model.CommonResponse[[]model.DDNSProfile]
// @Router /ddns [get]
func listDDNS(c *gin.Context) ([]*model.DDNSProfile, error) {
	var ddnsProfiles []*model.DDNSProfile

	list := singleton.DDNSShared.GetSortedList()
	if err := copier.Copy(&ddnsProfiles, &list); err != nil {
		return nil, err
	}
	for _, profile := range ddnsProfiles {
		decorateDDNSProfile(c, profile)
	}

	return ddnsProfiles, nil
}

// Add DDNS profile
// @Summary Add DDNS profile
// @Security BearerAuth
// @Schemes
// @Description Add DDNS profile
// @Tags auth required
// @Accept json
// @param request body model.DDNSForm true "DDNS Request"
// @Produce json
// @Success 200 {object} model.CommonResponse[uint64]
// @Router /ddns [post]
func createDDNS(c *gin.Context) (uint64, error) {
	var df model.DDNSForm
	var p model.DDNSProfile

	if err := c.ShouldBindJSON(&df); err != nil {
		return 0, err
	}

	if df.MaxRetries < 1 || df.MaxRetries > 10 {
		return 0, singleton.Localizer.ErrorT("the retry count must be an integer between 1 and 10")
	}

	p.UserID = getUid(c)
	if err := applyDDNSForm(c, &p, df); err != nil {
		return 0, err
	}

	if err := singleton.DB.Create(&p).Error; err != nil {
		return 0, newGormError("%v", err)
	}

	singleton.DDNSShared.Update(&p)
	return p.ID, nil
}

// Edit DDNS profile
// @Summary Edit DDNS profile
// @Security BearerAuth
// @Schemes
// @Description Edit DDNS profile
// @Tags auth required
// @Accept json
// @param id path uint true "Profile ID"
// @param request body model.DDNSForm true "DDNS Request"
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /ddns/{id} [patch]
func updateDDNS(c *gin.Context) (any, error) {
	idStr := c.Param("id")

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}

	var df model.DDNSForm
	if err := c.ShouldBindJSON(&df); err != nil {
		return nil, err
	}

	if df.MaxRetries < 1 || df.MaxRetries > 10 {
		return nil, singleton.Localizer.ErrorT("the retry count must be an integer between 1 and 10")
	}

	var p model.DDNSProfile
	if err = singleton.DB.First(&p, id).Error; err != nil {
		return nil, singleton.Localizer.ErrorT("profile id %d does not exist", id)
	}

	if !p.HasPermission(c) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	if err = applyDDNSForm(c, &p, df); err != nil {
		return nil, err
	}

	if err = singleton.DB.Save(&p).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	singleton.DDNSShared.Update(&p)

	return nil, nil
}

// Batch delete DDNS configurations
// @Summary Batch delete DDNS configurations
// @Security BearerAuth
// @Schemes
// @Description Batch delete DDNS configurations
// @Tags auth required
// @Accept json
// @param request body []uint64 true "id list"
// @Produce json
// @Success 200 {object} model.CommonResponse[any]
// @Router /batch-delete/ddns [post]
func batchDeleteDDNS(c *gin.Context) (any, error) {
	var ddnsConfigs []uint64

	if err := c.ShouldBindJSON(&ddnsConfigs); err != nil {
		return nil, err
	}

	if !singleton.DDNSShared.CheckPermission(c, slices.Values(ddnsConfigs)) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	if err := singleton.DB.Unscoped().Delete(&model.DDNSProfile{}, "id in (?)", ddnsConfigs).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	singleton.DDNSShared.Delete(ddnsConfigs)
	return nil, nil
}

// List DDNS Providers
// @Summary List DDNS providers
// @Schemes
// @Description List DDNS providers
// @Security BearerAuth
// @Tags auth required
// @Produce json
// @Success 200 {object} model.CommonResponse[[]string]
// @Router /ddns/providers [get]
func listProviders(c *gin.Context) ([]string, error) {
	return model.ProviderList[:], nil
}

func listDDNSCredential(c *gin.Context) ([]*model.DDNSCredential, error) {
	var credentials []*model.DDNSCredential

	list := singleton.DDNSCredentialShared.GetSortedList()
	if err := copier.Copy(&credentials, &list); err != nil {
		return nil, err
	}
	for _, credential := range credentials {
		credential.AccessSecretSet = credential.AccessSecret != ""
	}

	return credentials, nil
}

func createDDNSCredential(c *gin.Context) (uint64, error) {
	var form model.DDNSCredentialForm
	var credential model.DDNSCredential

	if err := c.ShouldBindJSON(&form); err != nil {
		return 0, err
	}
	if err := applyDDNSCredentialForm(&credential, form, false); err != nil {
		return 0, err
	}
	credential.UserID = getUid(c)

	if err := singleton.DB.Create(&credential).Error; err != nil {
		return 0, newGormError("%v", err)
	}

	singleton.DDNSCredentialShared.Update(&credential)
	return credential.ID, nil
}

func updateDDNSCredential(c *gin.Context) (any, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return nil, err
	}

	var form model.DDNSCredentialForm
	if err = c.ShouldBindJSON(&form); err != nil {
		return nil, err
	}

	var credential model.DDNSCredential
	if err = singleton.DB.First(&credential, id).Error; err != nil {
		return nil, singleton.Localizer.ErrorT("credential id %d does not exist", id)
	}
	if !credential.HasPermission(c) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}
	if err = applyDDNSCredentialForm(&credential, form, true); err != nil {
		return nil, err
	}

	if err = singleton.DB.Save(&credential).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	singleton.DDNSCredentialShared.Update(&credential)
	return nil, nil
}

func batchDeleteDDNSCredential(c *gin.Context) (any, error) {
	var ids []uint64

	if err := c.ShouldBindJSON(&ids); err != nil {
		return nil, err
	}
	if !singleton.DDNSCredentialShared.CheckPermission(c, slices.Values(ids)) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}

	var used int64
	if err := singleton.DB.Model(&model.DDNSProfile{}).Where("credential_id in ?", ids).Count(&used).Error; err != nil {
		return nil, newGormError("%v", err)
	}
	if used > 0 {
		return nil, singleton.Localizer.ErrorT("credential is still used by DDNS profiles")
	}

	if err := singleton.DB.Unscoped().Delete(&model.DDNSCredential{}, "id in (?)", ids).Error; err != nil {
		return nil, newGormError("%v", err)
	}

	singleton.DDNSCredentialShared.Delete(ids)
	return nil, nil
}

func applyDDNSForm(c *gin.Context, p *model.DDNSProfile, df model.DDNSForm) error {
	p.Name = df.Name
	enableIPv4 := df.EnableIPv4
	enableIPv6 := df.EnableIPv6
	p.EnableIPv4 = &enableIPv4
	p.EnableIPv6 = &enableIPv6
	p.MaxRetries = df.MaxRetries
	p.CredentialID = df.CredentialID
	p.Domains = df.Domains

	if p.CredentialID > 0 {
		credential, err := ddnsCredentialForUse(c, p.CredentialID)
		if err != nil {
			return err
		}
		applyDDNSCredential(p, credential)
	} else {
		p.Provider = df.Provider
		p.AccessID = df.AccessID
		p.AccessSecret = df.AccessSecret
		p.WebhookURL = df.WebhookURL
		p.WebhookMethod = df.WebhookMethod
		p.WebhookRequestType = df.WebhookRequestType
		p.WebhookRequestBody = df.WebhookRequestBody
		p.WebhookHeaders = df.WebhookHeaders
	}

	for n, domain := range p.Domains {
		domainValid, domainErr := idna.Lookup.ToASCII(domain)
		if domainErr != nil {
			return singleton.Localizer.ErrorT("error parsing %s: %v", domain, domainErr)
		}
		p.Domains[n] = domainValid
	}
	return nil
}

func applyDDNSCredentialForm(credential *model.DDNSCredential, form model.DDNSCredentialForm, preserveSecret bool) error {
	if !slices.Contains(model.ProviderList[:], form.Provider) {
		return singleton.Localizer.ErrorT("cannot find DDNS provider %s", form.Provider)
	}
	credential.Name = form.Name
	credential.Provider = form.Provider
	credential.AccessID = form.AccessID
	if !preserveSecret || form.AccessSecret != "" {
		credential.AccessSecret = form.AccessSecret
	}
	credential.WebhookURL = form.WebhookURL
	credential.WebhookMethod = form.WebhookMethod
	credential.WebhookRequestType = form.WebhookRequestType
	credential.WebhookRequestBody = form.WebhookRequestBody
	credential.WebhookHeaders = form.WebhookHeaders
	credential.AccessSecretSet = credential.AccessSecret != ""
	return nil
}

func ddnsCredentialForUse(c *gin.Context, id uint64) (*model.DDNSCredential, error) {
	credential, ok := singleton.DDNSCredentialShared.Get(id)
	if !ok {
		return nil, singleton.Localizer.ErrorT("credential id %d does not exist", id)
	}
	if !credential.HasPermission(c) {
		return nil, singleton.Localizer.ErrorT("permission denied")
	}
	return credential, nil
}

func applyDDNSCredential(p *model.DDNSProfile, credential *model.DDNSCredential) {
	p.Provider = credential.Provider
	p.AccessID = credential.AccessID
	p.AccessSecret = credential.AccessSecret
	p.WebhookURL = credential.WebhookURL
	p.WebhookMethod = credential.WebhookMethod
	p.WebhookRequestType = credential.WebhookRequestType
	p.WebhookRequestBody = credential.WebhookRequestBody
	p.WebhookHeaders = credential.WebhookHeaders
	p.CredentialName = credential.Name
}

func decorateDDNSProfile(c *gin.Context, p *model.DDNSProfile) {
	if p.CredentialID == 0 {
		return
	}
	credential, err := ddnsCredentialForUse(c, p.CredentialID)
	if err != nil {
		return
	}
	applyDDNSCredential(p, credential)
}
