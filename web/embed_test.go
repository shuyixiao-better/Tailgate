package webassets

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOfflineAssetsAreEmbedded(t *testing.T) {
	for _, path := range []string{"/", "/app.js", "/app.css", "/favicon.svg", "/vendor/xterm.js", "/vendor/xterm.css", "/vendor/addon-fit.js", "/vendor/xterm.LICENSE", "/vendor/addon-fit.LICENSE"} {
		request := httptest.NewRequest("GET", path, nil)
		response := httptest.NewRecorder()
		Handler().ServeHTTP(response, request)
		if response.Code != 200 || response.Body.Len() == 0 {
			t.Errorf("missing embedded asset %s: status %d", path, response.Code)
		}
	}
	index, err := files.Open("index.html")
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	content, err := io.ReadAll(index)
	if err != nil {
		t.Fatal(err)
	}
	for _, external := range []string{`src="http:`, `src="https:`, `href="https:`, `onclick=`, `<script>`} {
		if strings.Contains(string(content), external) {
			t.Errorf("frontend must remain offline and use external scripts: %s", external)
		}
	}
}

func TestMissingAssetIsNotASilentSPAResponse(t *testing.T) {
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest("GET", "/vendor/missing.js", nil))
	if response.Code != 404 {
		t.Fatalf("missing asset status = %d", response.Code)
	}
}
