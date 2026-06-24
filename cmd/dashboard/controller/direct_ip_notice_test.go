package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newDirectIPNoticeTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	oldNoticeFile := directIPNoticeFilePath
	noticeFile := filepath.Join(t.TempDir(), "notice.html")
	if err := os.WriteFile(noticeFile, []byte("<html>use domain</html>"), 0o644); err != nil {
		t.Fatalf("write notice fixture: %v", err)
	}
	directIPNoticeFilePath = noticeFile
	t.Cleanup(func() { directIPNoticeFilePath = oldNoticeFile })

	r := gin.New()
	r.Use(directIPNoticeMiddleware)
	r.GET("/*path", func(c *gin.Context) {
		c.String(http.StatusOK, "passed")
	})
	return r
}

func performDirectIPNoticeRequest(router *gin.Engine, host, path, accept string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	router.ServeHTTP(w, req)
	return w
}

func TestDirectIPNoticeShowsOnlyForBrowserHTMLOnPlainHost(t *testing.T) {
	router := newDirectIPNoticeTestRouter(t)

	w := performDirectIPNoticeRequest(router, "13.231.67.77:8008", "/", "text/html,application/xhtml+xml")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "use domain") {
		t.Fatalf("plain IP browser response = %d %q, want notice html", w.Code, w.Body.String())
	}

	w = performDirectIPNoticeRequest(router, "nz.666570.xyz", "/", "text/html")
	if w.Code != http.StatusOK || w.Body.String() != "passed" {
		t.Fatalf("domain browser response = %d %q, want pass-through", w.Code, w.Body.String())
	}

	w = performDirectIPNoticeRequest(router, "13.231.67.77:8008", "/api/v1/setting", "text/html")
	if w.Code != http.StatusOK || w.Body.String() != "passed" {
		t.Fatalf("API response = %d %q, want pass-through", w.Code, w.Body.String())
	}

	w = performDirectIPNoticeRequest(router, "13.231.67.77:8008", "/", "*/*")
	if w.Code != http.StatusOK || w.Body.String() != "passed" {
		t.Fatalf("non-html response = %d %q, want pass-through", w.Code, w.Body.String())
	}
}

func TestDirectIPNoticeSkipsWebSocket(t *testing.T) {
	router := newDirectIPNoticeTestRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/server", nil)
	req.Host = "13.231.67.77:8008"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Upgrade", "websocket")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK || w.Body.String() != "passed" {
		t.Fatalf("websocket response = %d %q, want pass-through", w.Code, w.Body.String())
	}
}
