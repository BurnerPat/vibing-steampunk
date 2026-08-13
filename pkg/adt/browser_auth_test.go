package adt

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestSaveCookiesToFile(t *testing.T) {
	cookies := map[string]string{
		"MYSAPSSO2":             "abc123",
		"sap-usercontext":       "sap-client=001",
		"SAP_SESSIONID_NPL_001": "session456",
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cookies.txt")

	err := SaveCookiesToFile(cookies, "https://sap.example.com:44300", path)
	if err != nil {
		t.Fatalf("SaveCookiesToFile failed: %v", err)
	}

	// Verify the file was created with restrictive permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cannot stat cookie file: %v", err)
	}

	// On Windows, the permission bits may not be meaningful, so we skip this check there
	if !strings.HasPrefix(strings.ToLower(os.Getenv("OS")), "windows") {
		if info.Mode().Perm() != 0600 {
			t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
		}
	}

	// Verify roundtrip: saved cookies can be loaded back
	loaded, err := LoadCookiesFromFile(path)
	if err != nil {
		t.Fatalf("LoadCookiesFromFile failed: %v", err)
	}
	if len(loaded) != len(cookies) {
		t.Errorf("expected %d cookies, got %d", len(cookies), len(loaded))
	}
	for name, expected := range cookies {
		if loaded[name] != expected {
			t.Errorf("cookie %s: expected %q, got %q", name, expected, loaded[name])
		}
	}
}

func TestSaveCookiesToFile_HTTPS(t *testing.T) {
	cookies := map[string]string{"test": "value"}
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cookies.txt")

	err := SaveCookiesToFile(cookies, "https://sap.example.com:44300", path)
	if err != nil {
		t.Fatalf("SaveCookiesToFile failed: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "TRUE\t/\tTRUE") {
		t.Error("expected secure flag TRUE for https URL")
	}
}

func TestSaveCookiesToFile_HTTP(t *testing.T) {
	cookies := map[string]string{"test": "value"}
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cookies.txt")

	err := SaveCookiesToFile(cookies, "http://sap.example.com:8000", path)
	if err != nil {
		t.Fatalf("SaveCookiesToFile failed: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "TRUE\t/\tFALSE") {
		t.Error("expected secure flag FALSE for http URL")
	}
}

func TestSaveCookiesToFile_InvalidURL(t *testing.T) {
	err := SaveCookiesToFile(map[string]string{"a": "b"}, "://bad", "/tmp/vsp_test_invalid.txt")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestBrowserLogin_InvalidURL(t *testing.T) {
	_, err := BrowserLogin(nil, "", false, 0, "", false)
	if err == nil {
		t.Error("expected error for empty URL")
	}

	_, err = BrowserLogin(nil, "not-a-url", false, 0, "", false)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestBuildBrowserProcessArgsUsesNativePasswordStore(t *testing.T) {
	args := buildBrowserProcessArgs(9222, "/tmp/vsp-browser", "sap.example.com", false)
	for _, arg := range args {
		switch arg {
		case "--password-store=basic", "--use-mock-keychain", "--disable-sync", "--disable-background-networking":
			t.Fatalf("browser argument %q prevents persistent password access", arg)
		}
	}
}

func TestBuildReentranceTicketURL(t *testing.T) {
	got, err := buildReentranceTicketURL("https://sap.example.com", "http://localhost:52682/adt/redirect")
	if err != nil {
		t.Fatalf("buildReentranceTicketURL() failed: %v", err)
	}
	if !strings.HasPrefix(got, "https://sap.example.com/sap/bc/adt/core/http/reentranceticket?") {
		t.Fatalf("unexpected login URL: %s", got)
	}
	if !strings.Contains(got, "redirect-url=http%3A%2F%2Flocalhost%3A52682%2Fadt%2Fredirect") {
		t.Fatalf("login URL does not contain encoded callback: %s", got)
	}
}

func TestResolveSystemURLs(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/sap/public/bc/icf/virtualhost" {
			t.Fatalf("request path = %q", req.URL.Path)
		}
		if req.Header.Get("Accept") != "application/json" {
			t.Fatalf("Accept = %q", req.Header.Get("Accept"))
		}
		fmt.Fprint(w, `{"relatedUrls":{"API":"https://api.example.com/","UI":"https://ui.example.com/ui"}}`)
	}))
	defer server.Close()

	apiURL, uiURL, err := resolveSystemURLs(context.Background(), server.URL, true)
	if err != nil {
		t.Fatalf("resolveSystemURLs() failed: %v", err)
	}
	if apiURL != "https://api.example.com" {
		t.Fatalf("API URL = %q", apiURL)
	}
	if uiURL != "https://ui.example.com" {
		t.Fatalf("UI URL = %q", uiURL)
	}
}

func TestExchangeReentranceTicket(t *testing.T) {
	var gotTicket string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/sap/bc/adt/core/http/sessions":
			gotTicket = req.Header.Get("MYSAPSSO2")
			if req.Header.Get("Accept") != sessionInformationAccept {
				t.Fatalf("Accept = %q", req.Header.Get("Accept"))
			}
			if req.Header.Get("sap-adt-purpose") != "preflight_logon" {
				t.Fatalf("sap-adt-purpose = %q", req.Header.Get("sap-adt-purpose"))
			}
			if req.Header.Get("sap-client") != "100" || req.Header.Get("sap-language") != "EN" {
				t.Fatalf("SAP client/language headers = %q/%q", req.Header.Get("sap-client"), req.Header.Get("sap-language"))
			}
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "provisional", Path: "/"})
			fmt.Fprintf(w, `<session><link rel="%s" href="/sap/bc/adt/core/http/systeminformation" type="application/xml"/></session>`, systemInformationRelation)
		case "/sap/bc/adt/core/http/systeminformation":
			if req.Header.Get("x-sap-security-session") != "use" {
				t.Fatalf("x-sap-security-session = %q, want use", req.Header.Get("x-sap-security-session"))
			}
			http.SetCookie(w, &http.Cookie{Name: "SAP_SESSIONID_TEST_001", Value: "session", Path: "/"})
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request path: %s", req.URL.Path)
		}
	}))
	defer server.Close()

	cookies, err := exchangeReentranceTicket(context.Background(), server.URL, "ticket-value", "100", "EN", true)
	if err != nil {
		t.Fatalf("exchangeReentranceTicket() failed: %v", err)
	}
	if gotTicket != "ticket-value" {
		t.Fatalf("MYSAPSSO2 header = %q, want ticket-value", gotTicket)
	}
	if cookies["SAP_SESSIONID_TEST_001"] != "session" {
		t.Fatalf("session cookie not returned: %#v", cookies)
	}
}

func TestExchangeReentranceTicketRejectsMissingSAPSession(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/sap/bc/adt/core/http/sessions" {
			fmt.Fprintf(w, `<session><link rel="%s" href="/systeminformation" type="application/xml"/></session>`, systemInformationRelation)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := exchangeReentranceTicket(context.Background(), server.URL, "ticket-value", "", "", true)
	if err == nil || !strings.Contains(err.Error(), "no SAP session cookie") {
		t.Fatalf("exchangeReentranceTicket() error = %v, want missing SAP session cookie", err)
	}
}

func TestExchangeReentranceTicketRejectsRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/login", http.StatusFound)
	}))
	defer server.Close()

	_, err := exchangeReentranceTicket(context.Background(), server.URL, "ticket-value", "100", "EN", true)
	if err == nil || !strings.Contains(err.Error(), "302 Found") {
		t.Fatalf("exchangeReentranceTicket() error = %v, want redirect rejection", err)
	}
}

func TestExchangeReentranceTicketRejectsLoginHTML(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><script>location.href="/login?client_id=test"</script></html>`)
	}))
	defer server.Close()

	_, err := exchangeReentranceTicket(context.Background(), server.URL, "ticket-value", "100", "EN", true)
	if err == nil || !strings.Contains(err.Error(), "ticket was not accepted") {
		t.Fatalf("exchangeReentranceTicket() error = %v, want rejected ticket", err)
	}
}

func TestBrowserDataDirPersists(t *testing.T) {
	want := filepath.Join(t.TempDir(), "edge-profile")
	t.Setenv("VSP_BROWSER_DATA_DIR", want)

	first, err := browserDataDir("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")
	if err != nil {
		t.Fatalf("browserDataDir() failed: %v", err)
	}
	second, err := browserDataDir("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")
	if err != nil {
		t.Fatalf("browserDataDir() failed: %v", err)
	}
	if first != want || second != want {
		t.Fatalf("browserDataDir() = %q, %q; want persistent path %q", first, second, want)
	}
	if info, err := os.Stat(want); err != nil || !info.IsDir() {
		t.Fatalf("persistent browser profile was not created: %v", err)
	}
}

func TestHasSAPAuthCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookies    []*network.Cookie
		currentURL string
		want       bool
	}{
		{
			name:       "pre-login JSESSIONID at identity provider",
			cookies:    []*network.Cookie{{Name: "JSESSIONID"}},
			currentURL: "https://systems-login.example.com/auth/login",
			want:       false,
		},
		{
			name:       "BTP JSESSIONID after returning to SAP host",
			cookies:    []*network.Cookie{{Name: "JSESSIONID"}},
			currentURL: "https://sap.example.com:44300/sap/bc/adt/",
			want:       true,
		},
		{
			name:       "BTP JSESSIONID during login callback",
			cookies:    []*network.Cookie{{Name: "JSESSIONID"}},
			currentURL: "https://sap.example.com:44300/login/callback?code=example",
			want:       false,
		},
		{
			name:       "SAP session cookie during redirect",
			cookies:    []*network.Cookie{{Name: "SAP_SESSIONID_A4H_001"}},
			currentURL: "https://login.example.com/",
			want:       true,
		},
		{
			name:       "weak cookie after returning to SAP host",
			cookies:    []*network.Cookie{{Name: "sap-usercontext"}},
			currentURL: "https://sap.example.com:44300/sap/bc/adt/",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSAPAuthCookie(tt.cookies, tt.currentURL, "https://sap.example.com:44300")
			if got != tt.want {
				t.Fatalf("hasSAPAuthCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildBrowserAuthTargetURL(t *testing.T) {
	base := "https://sap.example.com:44300"

	t.Run("default target", func(t *testing.T) {
		got, err := buildBrowserAuthTargetURL(base, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://sap.example.com:44300/sap/bc/adt/"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("absolute path override", func(t *testing.T) {
		got, err := buildBrowserAuthTargetURL(base, "/sap/public/ping")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://sap.example.com:44300/sap/public/ping"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("root path override", func(t *testing.T) {
		got, err := buildBrowserAuthTargetURL(base, "/")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://sap.example.com:44300/"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("relative path override", func(t *testing.T) {
		got, err := buildBrowserAuthTargetURL(base, "sap/public/ping")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://sap.example.com:44300/sap/public/ping"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("absolute URL override", func(t *testing.T) {
		got, err := buildBrowserAuthTargetURL(base, "https://idp.example.com/login")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "https://idp.example.com/login"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("invalid override URL", func(t *testing.T) {
		_, err := buildBrowserAuthTargetURL(base, "https://")
		if err == nil {
			t.Fatal("expected error for invalid override URL")
		}
	})
}
