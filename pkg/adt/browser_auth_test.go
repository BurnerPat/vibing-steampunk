package adt

import (
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
