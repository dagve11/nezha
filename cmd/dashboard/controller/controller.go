package controller

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/nezhahq/nezha/cmd/dashboard/controller/waf"
	docs "github.com/nezhahq/nezha/cmd/dashboard/docs"
	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
	"github.com/nezhahq/nezha/service/singleton"
)

const defaultFrontendTitle = "哪吒监控 Nezha Monitoring"

var frontendTitleTagPattern = regexp.MustCompile(`(?is)<title>.*?</title>`)

func ServeWeb(frontendDist fs.FS) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	if singleton.Conf.Debug {
		gin.SetMode(gin.DebugMode)
		pprof.Register(r)
	}
	if singleton.Conf.Debug {
		log.Printf("NEZHA>> Swagger(%s) UI available at http://localhost:%d/swagger/index.html", docs.SwaggerInfo.Version, singleton.Conf.ListenPort)
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	}

	r.Use(waf.RealIp)
	r.Use(waf.Waf)
	r.Use(recordPath)

	routers(r, frontendDist)

	return r
}

func routers(r *gin.Engine, frontendDist fs.FS) {
	authMiddleware, err := jwt.New(initParams())
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}
	if err := authMiddleware.MiddlewareInit(); err != nil {
		log.Fatal("authMiddleware.MiddlewareInit Error:" + err.Error())
	}
	api := r.Group("api/v1")
	api.POST("/login", authMiddleware.LoginHandler)
	api.GET("/oauth2/:provider", commonHandler(oauth2redirect))

	fallbackAuthMw := fallbackAuthMiddleware(authMiddleware)
	fallbackAuth := api.Group("", fallbackAuthMw)
	fallbackAuth.GET("/setting", commonHandler(listConfig))
	fallbackAuth.GET("/oauth2/callback", commonHandler(oauth2callback(authMiddleware)))

	authMw := authMiddleware.MiddlewareFunc()
	optionalAuthMw := utils.IfOr(singleton.Conf.ForceAuth, authMw, fallbackAuthMw)

	optionalAuth := api.Group("", optionalAuthMw)
	optionalAuth.GET("/ws/server", commonHandler(serverStream))
	optionalAuth.GET("/server-group", commonHandler(listServerGroup))

	optionalAuth.GET("/service", commonHandler(showService))
	optionalAuth.GET("/service/server", commonHandler(listServerWithServices))
	optionalAuth.GET("/service/:id/history", commonHandler(getServiceHistory))
	optionalAuth.GET("/server/:id/service", commonHandler(listServerServices))
	optionalAuth.GET("/server/:id/metrics", commonHandler(getServerMetrics))

	auth := api.Group("", authMw)

	auth.GET("/refresh-token", authMiddleware.RefreshHandler)

	auth.POST("/terminal", commonHandler(createTerminal))
	auth.GET("/ws/terminal/:id", commonHandler(terminalStream))

	auth.POST("/file", commonHandler(createFM))
	auth.GET("/ws/file/:id", commonHandler(fmStream))

	auth.GET("/profile", commonHandler(getProfile))
	auth.POST("/profile", commonHandler(updateProfile))
	auth.POST("/oauth2/:provider/unbind", commonHandler(unbindOauth2))

	auth.GET("/user", adminHandler(listUser))
	auth.POST("/user", adminHandler(createUser))
	auth.PATCH("/user/:id", adminHandler(updateUser))
	auth.POST("/batch-delete/user", adminHandler(batchDeleteUser))

	serviceAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureService))
	serviceAuth.GET("/service/list", listHandler(listService))
	serviceAuth.POST("/service", commonHandler(createService))
	serviceAuth.PATCH("/service/:id", commonHandler(updateService))
	serviceAuth.POST("/batch-delete/service", commonHandler(batchDeleteService))

	serverGroupAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureServerGroup))
	serverGroupAuth.POST("/server-group", commonHandler(createServerGroup))
	serverGroupAuth.PATCH("/server-group/:id", commonHandler(updateServerGroup))
	serverGroupAuth.POST("/batch-delete/server-group", commonHandler(batchDeleteServerGroup))

	auth.GET("/notification-group", commonHandler(listNotificationGroup))
	notificationAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureNotification))
	notificationAuth.POST("/notification-group", commonHandler(createNotificationGroup))
	notificationAuth.PATCH("/notification-group/:id", commonHandler(updateNotificationGroup))
	notificationAuth.POST("/batch-delete/notification-group", commonHandler(batchDeleteNotificationGroup))

	auth.GET("/server", listHandler(listServer))
	auth.PATCH("/server/:id", commonHandler(updateServer))
	auth.GET("/server/config/:id", commonHandler(getServerConfig))
	auth.POST("/server/config", commonHandler(setServerConfig))
	auth.POST("/batch-delete/server", commonHandler(batchDeleteServer))
	auth.POST("/force-update/server", commonHandler(forceUpdateServer))

	serverTransferAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureServerTransfer))
	serverTransferAuth.POST("/batch-move/server", commonHandler(batchMoveServer))
	serverTransferAuth.GET("/transfer", listHandler(listServerTransfer))
	serverTransferAuth.POST("/transfer/:id/cancel", commonHandler(cancelServerTransfer))
	serverTransferAuth.POST("/transfer/:id/retry", commonHandler(retryServerTransfer))
	serverTransferAuth.GET("/ws/transfer", commonHandler(transferStream))

	notificationAuth.GET("/notification", listHandler(listNotification))
	notificationAuth.POST("/notification", commonHandler(createNotification))
	notificationAuth.PATCH("/notification/:id", commonHandler(updateNotification))
	notificationAuth.POST("/batch-delete/notification", commonHandler(batchDeleteNotification))

	notificationAuth.GET("/alert-rule", listHandler(listAlertRule))
	notificationAuth.POST("/alert-rule", commonHandler(createAlertRule))
	notificationAuth.PATCH("/alert-rule/:id", commonHandler(updateAlertRule))
	notificationAuth.POST("/batch-delete/alert-rule", commonHandler(batchDeleteAlertRule))

	taskAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureTask))
	taskAuth.GET("/cron", listHandler(listCron))
	taskAuth.POST("/cron", commonHandler(createCron))
	taskAuth.PATCH("/cron/:id", commonHandler(updateCron))
	taskAuth.POST("/cron/:id/manual", commonHandler(manualTriggerCron))
	taskAuth.POST("/batch-delete/cron", commonHandler(batchDeleteCron))

	auth.GET("/ddns", listHandler(listDDNS))
	auth.GET("/ddns/providers", commonHandler(listProviders))
	auth.GET("/ddns-credential", listHandler(listDDNSCredential))
	ddnsAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureDDNS))
	ddnsAuth.POST("/ddns-credential", commonHandler(createDDNSCredential))
	ddnsAuth.PATCH("/ddns-credential/:id", commonHandler(updateDDNSCredential))
	ddnsAuth.POST("/ddns", commonHandler(createDDNS))
	ddnsAuth.PATCH("/ddns/:id", commonHandler(updateDDNS))
	ddnsAuth.POST("/batch-delete/ddns", commonHandler(batchDeleteDDNS))
	ddnsAuth.POST("/batch-delete/ddns-credential", commonHandler(batchDeleteDDNSCredential))

	bestIPAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureBestIP))
	bestIPAuth.POST("/bestip/fission", commonHandler(runBestIPFission))
	bestIPAuth.GET("/ws/bestip/fission", commonHandler(streamBestIPFission))
	bestIPAuth.POST("/bestip/dns", commonHandler(writeBestIPDNS))
	bestIPAuth.POST("/bestip/notify", commonHandler(notifyBestIPResult))
	bestIPAuth.GET("/bestip/automation", commonHandler(getBestIPAutomation))
	bestIPAuth.POST("/bestip/automation", commonHandler(saveBestIPAutomation))
	bestIPAuth.POST("/bestip/automation/run", commonHandler(runBestIPAutomation))
	bestIPAuth.POST("/bestip/automation/rollback", commonHandler(rollbackBestIPAutomation))
	bestIPAuth.GET("/bestip/automation/history", commonHandler(listBestIPAutomationHistory))

	natAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureNAT))
	natAuth.GET("/nat", listHandler(listNAT))
	natAuth.POST("/nat", commonHandler(createNAT))
	natAuth.PATCH("/nat/:id", commonHandler(updateNAT))
	natAuth.POST("/batch-delete/nat", commonHandler(batchDeleteNAT))

	vpnAuth := auth.Group("", userFeatureMiddleware(model.UserFeatureVPN))
	vpnAuth.GET("/vpn/policy", commonHandler(listVPNPolicy))
	vpnAuth.POST("/vpn/policy", commonHandler(createVPNPolicy))
	vpnAuth.PATCH("/vpn/policy/:id", commonHandler(updateVPNPolicy))
	vpnAuth.POST("/batch-delete/vpn/policy", commonHandler(batchDeleteVPNPolicy))
	vpnAuth.POST("/vpn/policy/:id/core/prepare", commonHandler(prepareVPNPolicyCore))
	vpnAuth.POST("/vpn/policy/:id/core/cleanup", commonHandler(cleanupVPNPolicyCore))
	vpnAuth.POST("/vpn/policy/:id/rules/prepare", commonHandler(prepareVPNPolicyRules))
	vpnAuth.POST("/vpn/policy/:id/rules/cleanup", commonHandler(cleanupVPNPolicyRules))
	vpnAuth.POST("/vpn/policy/:id/status", commonHandler(statusVPNPolicy))
	vpnAuth.GET("/vpn/debug/agent-results", commonHandler(listVPNAgentDebugResults))
	vpnAuth.GET("/vpn/session", commonHandler(listVPNSession))
	vpnAuth.POST("/vpn/session/start", commonHandler(startVPNSession))
	vpnAuth.POST("/vpn/session/:id/stop", commonHandler(stopVPNSession))
	vpnAuth.POST("/vpn/session/:id/delete", commonHandler(deleteVPNSession))
	vpnAuth.POST("/vpn/session/:id/restart", commonHandler(restartVPNSession))
	vpnAuth.POST("/vpn/session/:id/status", commonHandler(statusVPNSession))
	vpnAuth.POST("/vpn/session/:id/control", commonHandler(controlVPNSession))
	vpnAuth.GET("/ws/vpn/session/:id", commonHandler(vpnSessionStream))
	vpnAuth.GET("/vpn/audit", commonHandler(listVPNAudit))

	auth.GET("/waf", pAdminHandler(listBlockedAddress))
	auth.POST("/batch-delete/waf", adminHandler(batchDeleteBlockedAddress))

	auth.GET("/online-user", pAdminHandler(listOnlineUser))
	auth.POST("/online-user/batch-block", adminHandler(batchBlockOnlineUser))

	auth.PATCH("/setting", adminHandler(updateConfig))
	auth.POST("/maintenance", adminHandler(runMaintenance))

	r.NoRoute(fallbackToFrontend(frontendDist))
}

func recordPath(c *gin.Context) {
	url := c.Request.URL.String()
	for _, p := range c.Params {
		url = strings.Replace(url, p.Value, ":"+p.Key, 1)
	}
	c.Set("MatchedPath", url)
}

func newErrorResponse(err error) model.CommonResponse[any] {
	return model.CommonResponse[any]{
		Success: false,
		Error:   err.Error(),
	}
}

type handlerFunc[T any] func(c *gin.Context) (T, error)
type pHandlerFunc[S ~[]E, E any] func(c *gin.Context) (*model.Value[S], error)

// There are many error types in gorm, so create a custom type to represent all
// gorm errors here instead
type gormError struct {
	msg string
	a   []any
}

func newGormError(format string, args ...any) error {
	return &gormError{
		msg: format,
		a:   args,
	}
}

func (ge *gormError) Error() string {
	return fmt.Sprintf(ge.msg, ge.a...)
}

type wsError struct {
	msg string
	a   []any
}

func newWsError(format string, args ...any) error {
	return &wsError{
		msg: format,
		a:   args,
	}
}

func (we *wsError) Error() string {
	return fmt.Sprintf(we.msg, we.a...)
}

var errNoop = errors.New("wrote")

func commonHandler[T any](handler handlerFunc[T]) func(*gin.Context) {
	return func(c *gin.Context) {
		handle(c, handler)
	}
}

func adminHandler[T any](handler handlerFunc[T]) func(*gin.Context) {
	return func(c *gin.Context) {
		auth, ok := c.Get(model.CtxKeyAuthorizedUser)
		if !ok {
			c.JSON(http.StatusOK, newErrorResponse(singleton.Localizer.ErrorT("unauthorized")))
			return
		}

		user := *auth.(*model.User)
		if !user.Role.IsAdmin() {
			c.JSON(http.StatusOK, newErrorResponse(singleton.Localizer.ErrorT("permission denied")))
			return
		}

		handle(c, handler)
	}
}

func handle[T any](c *gin.Context, handler handlerFunc[T]) {
	data, err := handler(c)
	if err == nil {
		c.JSON(http.StatusOK, model.CommonResponse[T]{Success: true, Data: data})
		return
	}
	switch err.(type) {
	case *gormError:
		log.Printf("NEZHA>> gorm error: %v", err)
		c.JSON(http.StatusOK, newErrorResponse(singleton.Localizer.ErrorT("database error")))
		return
	case *wsError:
		// Connection is upgraded to WebSocket, so c.Writer is no longer usable
		if msg := err.Error(); msg != "" {
			log.Printf("NEZHA>> websocket error: %v", err)
		}
		return
	default:
		if !errors.Is(err, errNoop) {
			c.JSON(http.StatusOK, newErrorResponse(err))
		}
		return
	}
}

func listHandler[S ~[]E, E model.CommonInterface](handler handlerFunc[S]) func(*gin.Context) {
	return func(c *gin.Context) {
		data, err := handler(c)
		if err != nil {
			c.JSON(http.StatusOK, newErrorResponse(err))
			return
		}

		filtered := filter(c, data)
		c.JSON(http.StatusOK, model.CommonResponse[S]{Success: true, Data: model.SearchByIDCtx(c, filtered)})
	}
}

func pCommonHandler[S ~[]E, E any](handler pHandlerFunc[S, E]) func(*gin.Context) {
	return func(c *gin.Context) {
		data, err := handler(c)
		if err != nil {
			c.JSON(http.StatusOK, newErrorResponse(err))
			return
		}

		c.JSON(http.StatusOK, model.PaginatedResponse[S, E]{Success: true, Data: data})
	}
}

func pAdminHandler[S ~[]E, E any](handler pHandlerFunc[S, E]) func(*gin.Context) {
	return func(c *gin.Context) {
		auth, ok := c.Get(model.CtxKeyAuthorizedUser)
		if !ok {
			c.JSON(http.StatusOK, newErrorResponse(singleton.Localizer.ErrorT("unauthorized")))
			return
		}
		user := *auth.(*model.User)
		if !user.Role.IsAdmin() {
			c.JSON(http.StatusOK, newErrorResponse(singleton.Localizer.ErrorT("permission denied")))
			return
		}

		data, err := handler(c)
		if err != nil {
			c.JSON(http.StatusOK, newErrorResponse(err))
			return
		}

		c.JSON(http.StatusOK, model.PaginatedResponse[S, E]{Success: true, Data: data})
	}
}

func filter[S ~[]E, E model.CommonInterface](ctx *gin.Context, s S) S {
	return slices.DeleteFunc(s, func(e E) bool {
		return !e.HasPermission(ctx)
	})
}

func getUid(c *gin.Context) uint64 {
	user, _ := c.MustGet(model.CtxKeyAuthorizedUser).(*model.User)
	return user.ID
}

func frontendIndexTitle() string {
	title := defaultFrontendTitle
	if singleton.Conf != nil && strings.TrimSpace(singleton.Conf.SiteName) != "" {
		title = strings.TrimSpace(singleton.Conf.SiteName)
	}
	return "<title>" + html.EscapeString(title) + "</title>"
}

func injectFrontendIndexTitle(content []byte) []byte {
	return frontendTitleTagPattern.ReplaceAll(content, []byte(frontendIndexTitle()))
}

func fallbackToFrontend(frontendDist fs.FS) func(*gin.Context) {
	serveFile := func(c *gin.Context, name string, file fs.File, customStatusCode int) bool {
		defer file.Close()
		fileStat, err := file.Stat()
		if err != nil {
			return false
		}
		if fileStat.IsDir() {
			return false
		}
		readSeeker, ok := file.(io.ReadSeeker)
		if !ok {
			return false
		}
		if name == "index.html" {
			content, err := io.ReadAll(readSeeker)
			if err != nil {
				return false
			}
			http.ServeContent(utils.NewGinCustomWriter(c, customStatusCode), c.Request, name, fileStat.ModTime(), bytes.NewReader(injectFrontendIndexTitle(content)))
			return true
		}
		http.ServeContent(utils.NewGinCustomWriter(c, customStatusCode), c.Request, name, fileStat.ModTime(), readSeeker)
		return true
	}

	checkLocalFileOrFs := func(c *gin.Context, frontendFS fs.FS, templateRoot, filePath string, customStatusCode int) bool {
		if filePath != "" {
			localRoot, err := os.OpenRoot(templateRoot)
			if err == nil {
				defer localRoot.Close()
				// URL paths must stay inside the selected template root; never join them against the process cwd.
				if file, err := localRoot.Open(filePath); err == nil && serveFile(c, filePath, file, customStatusCode) {
					return true
				}
			}
		}

		if !fs.ValidPath(filePath) {
			return false
		}
		templateFS, err := fs.Sub(frontendFS, templateRoot)
		if err != nil {
			return false
		}
		file, err := templateFS.Open(filePath)
		if err != nil {
			return false
		}
		if serveFile(c, filePath, file, customStatusCode) {
			return true
		}
		return false
	}

	frontendPageUrlRegistry := []*regexp.Regexp{
		// official user frontend
		regexp.MustCompile(`^/$`),
		regexp.MustCompile(`^/server/\d*$`),
		// backend frontend
		regexp.MustCompile(`^/dashboard/$`),
		regexp.MustCompile(`^/dashboard/login$`),
		regexp.MustCompile(`^/dashboard/service$`),
		regexp.MustCompile(`^/dashboard/cron$`),
		regexp.MustCompile(`^/dashboard/notification$`),
		regexp.MustCompile(`^/dashboard/alert-rule$`),
		regexp.MustCompile(`^/dashboard/ddns$`),
		regexp.MustCompile(`^/dashboard/bestip$`),
		regexp.MustCompile(`^/dashboard/nat$`),
		regexp.MustCompile(`^/dashboard/vpn$`),
		regexp.MustCompile(`^/dashboard/terminal/\d+$`),
		regexp.MustCompile(`^/dashboard/server-group$`),
		regexp.MustCompile(`^/dashboard/notification-group$`),
		regexp.MustCompile(`^/dashboard/profile$`),
		regexp.MustCompile(`^/dashboard/settings$`),
		regexp.MustCompile(`^/dashboard/settings/user$`),
		regexp.MustCompile(`^/dashboard/settings/online-user$`),
		regexp.MustCompile(`^/dashboard/settings/waf$`),
		// 注意：这里的白名单决定哪些 URL 走 index.html fallback；漏一条就会把
		// 直接刷新该页面变成 404（HTTP 状态码层面，body 仍是 index.html，所以
		// 浏览器内 SPA 看起来正常，但 monitoring / 链接预览会以为站点挂了）。
		// 新增前端路由时必须在 admin-frontend/src/main.tsx 与这里同步加。
		regexp.MustCompile(`^/dashboard/transfer$`),
	}

	getFallbackStatusCode := func(path string) int {
		for _, reg := range frontendPageUrlRegistry {
			if reg.MatchString(path) {
				return http.StatusOK
			}
		}
		return http.StatusNotFound
	}

	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.JSON(http.StatusNotFound, newErrorResponse(errors.New("404 Not Found")))
			return
		}

		// redirect for /dashboard to /dashboard/
		if c.Request.URL.Path == "/dashboard" {
			c.Redirect(http.StatusMovedPermanently, "/dashboard/")
			return
		}

		fallbackStatusCode := getFallbackStatusCode(c.Request.URL.Path)
		// Only /dashboard/ belongs to the admin frontend; /dashboard.. must not be trimmed into ../.
		if strings.HasPrefix(c.Request.URL.Path, "/dashboard/") {
			stripPath := strings.TrimPrefix(c.Request.URL.Path, "/dashboard/")
			if checkLocalFileOrFs(c, frontendDist, singleton.Conf.AdminTemplate, stripPath, http.StatusOK) {
				return
			}
			if !checkLocalFileOrFs(c, frontendDist, singleton.Conf.AdminTemplate, "index.html", fallbackStatusCode) {
				c.JSON(http.StatusNotFound, newErrorResponse(errors.New("404 Not Found")))
			}
			return
		}
		stripPath := strings.TrimPrefix(c.Request.URL.Path, "/")
		if checkLocalFileOrFs(c, frontendDist, singleton.Conf.UserTemplate, stripPath, http.StatusOK) {
			return
		}
		if !checkLocalFileOrFs(c, frontendDist, singleton.Conf.UserTemplate, "index.html", fallbackStatusCode) {
			c.JSON(http.StatusNotFound, newErrorResponse(errors.New("404 Not Found")))
		}
	}
}
