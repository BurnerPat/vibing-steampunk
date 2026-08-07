package adt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// sapCookieNames are cookie name prefixes that indicate successful SAP authentication.
// These are strong signals — their presence means the user is actually authenticated.
var sapAuthCookieNames = []string{
	"MYSAPSSO2",
	"SAP_SESSIONID",
}

const btpAuthCookieName = "JSESSIONID"

// sapWeakCookieNames are set before/during authentication and are not sufficient alone.
var sapWeakCookieNames = []string{
	"sap-usercontext",
}

// browserCandidates lists Chromium-based browsers to search for, in preference order.
// chromedp requires a Chromium-based browser (Chrome, Edge, Brave, Chromium).
var browserCandidates = map[string][]string{
	"windows": {
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
	},
	"linux": {
		"microsoft-edge",
		"microsoft-edge-stable",
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"brave-browser",
	},
	"darwin": {
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	},
}

// FindBrowser searches for an installed Chromium-based browser.
// Returns the executable path and a friendly name, or empty strings if none found.
func FindBrowser() (path string, name string) {
	candidates := browserCandidates[runtime.GOOS]
	for _, candidate := range candidates {
		if runtime.GOOS == "windows" {
			// On Windows, check absolute paths directly
			if _, err := os.Stat(candidate); err == nil {
				return candidate, friendlyBrowserName(candidate)
			}
		} else {
			// On Linux/macOS, try both absolute path and PATH lookup
			if _, err := os.Stat(candidate); err == nil {
				return candidate, friendlyBrowserName(candidate)
			}
			if p, err := exec.LookPath(candidate); err == nil {
				return p, friendlyBrowserName(candidate)
			}
		}
	}
	return "", ""
}

func friendlyBrowserName(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "edge") || strings.Contains(lower, "msedge"):
		return "Microsoft Edge"
	case strings.Contains(lower, "brave"):
		return "Brave"
	case strings.Contains(lower, "chromium"):
		return "Chromium"
	default:
		return "Google Chrome"
	}
}

// buildBrowserAuthTargetURL resolves the browser navigation target.
// Default behavior is to append /sap/bc/adt/ to sapURL for backward compatibility.
func buildBrowserAuthTargetURL(sapURL, override string) (string, error) {
	u, err := url.Parse(sapURL)
	if err != nil {
		return "", fmt.Errorf("invalid SAP URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid SAP URL (missing scheme or host): %s", sapURL)
	}

	baseURL := strings.TrimRight(sapURL, "/")
	override = strings.TrimSpace(override)
	if override == "" {
		return baseURL + "/sap/bc/adt/", nil
	}

	parsed, err := url.Parse(override)
	if err != nil {
		return "", fmt.Errorf("invalid browser auth URL override: %w", err)
	}

	if parsed.IsAbs() {
		if parsed.Host == "" {
			return "", fmt.Errorf("invalid browser auth URL override (missing host): %s", override)
		}
		return parsed.String(), nil
	}

	if strings.HasPrefix(override, "/") {
		return baseURL + override, nil
	}

	return baseURL + "/" + override, nil
}

// BrowserLogin opens a headed browser window to the SAP system URL, waits for
// SSO authentication to complete (Kerberos/SPNEGO, Keycloak, SAML, etc.),
// and returns the session cookies.
//
// If execPath is empty, it auto-detects an installed Chromium-based browser
// (Edge, Chrome, Chromium, Brave). Set execPath to force a specific browser.
//
// The browser navigates to the ADT discovery endpoint which requires authentication,
// triggering the SSO redirect. Once SAP-specific cookies appear, they are extracted
// and the browser is closed.
//
// We launch the browser process manually and connect via RemoteAllocator instead
// of using chromedp's ExecAllocator. ExecAllocator has a known race condition
// where its cmd.Wait goroutine can panic with "close of closed channel" when the
// browser process exits unexpectedly (common in MCP host environments like VS Code
// that manage child process lifecycles).
func BrowserLogin(ctx context.Context, sapURL string, insecure bool, timeout time.Duration, execPath string, verbose bool) (map[string]string, error) {
	return BrowserLoginWithTarget(ctx, sapURL, "", insecure, timeout, execPath, verbose)
}

// BrowserLoginWithTarget behaves like BrowserLogin but allows overriding
// the browser navigation target URL (absolute URL or URL path).
func BrowserLoginWithTarget(ctx context.Context, sapURL, targetOverride string, insecure bool, timeout time.Duration, execPath string, verbose bool) (map[string]string, error) {
	u, err := url.Parse(sapURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SAP URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid SAP URL (missing scheme or host): %s", sapURL)
	}

	// Target URL that requires authentication and renders HTML.
	// We use the ADT root which returns an HTML page after auth.
	// The /sap/bc/adt/core/discovery endpoint returns XML which browsers
	// try to download as a file, breaking the flow.
	targetURL, err := buildBrowserAuthTargetURL(sapURL, targetOverride)
	if err != nil {
		return nil, err
	}

	// Determine which browser to use
	browserName := "browser"
	if execPath != "" {
		if _, err := os.Stat(execPath); os.IsNotExist(err) {
			if resolved, lookErr := exec.LookPath(execPath); lookErr == nil {
				execPath = resolved
			} else {
				return nil, fmt.Errorf("browser executable not found: %s", execPath)
			}
		}
		browserName = friendlyBrowserName(execPath)
	} else {
		if found, name := FindBrowser(); found != "" {
			execPath = found
			browserName = name
		} else {
			return nil, fmt.Errorf("no Chromium-based browser found. Install Edge, Chrome, or Chromium, or use --browser-exec to specify the path")
		}
	}

	// Launch browser manually and get DevTools WebSocket URL.
	// We manage the process ourselves to avoid chromedp ExecAllocator's
	// goroutine race condition on browser process exit.
	wsURL, cmd, dataDir, debugPort, err := launchBrowserProcess(ctx, execPath, u.Host, insecure, verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to launch %s: %w", browserName, err)
	}
	defer cleanupBrowser(cmd, dataDir)

	// Connect to the browser via RemoteAllocator (no ExecAllocator goroutines).
	allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, wsURL)
	defer allocCancel()

	// Attach to the existing tab instead of creating a new one.
	// Edge opens one tab on startup (about:blank); we reuse it via its target ID.
	targetID, err := findFirstTarget(debugPort)
	if err != nil {
		// Fallback: create a new context (will create a second tab)
		if verbose {
			fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Could not find existing tab, creating new one: %v\n", err)
		}
	}

	var browserCtx context.Context
	var browserCancel context.CancelFunc
	if targetID != "" {
		browserCtx, browserCancel = chromedp.NewContext(allocCtx, chromedp.WithTargetID(target.ID(targetID)))
	} else {
		browserCtx, browserCancel = chromedp.NewContext(allocCtx)
	}
	defer browserCancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(browserCtx, timeout)
	defer timeoutCancel()

	fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Opening %s for SSO login: %s\n", browserName, targetURL)
	fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Complete login in the browser window. Timeout: %s\n", timeout)

	// Navigate to the target URL (this triggers SSO redirect).
	// SSO flows (Kerberos 401, SAML redirect, etc.) often cause the initial
	// navigation to report ERR_ABORTED or similar — this is expected.
	// The browser stays open and the SSO handshake continues, so we ignore
	// page-load navigation errors and proceed to cookie polling.
	if err := chromedp.Run(timeoutCtx, chromedp.Navigate(targetURL)); err != nil {
		if timeoutCtx.Err() != nil {
			return nil, fmt.Errorf("browser auth timed out after %s — login was not completed", timeout)
		}
		errMsg := err.Error()
		if strings.Contains(errMsg, "executable file not found") ||
			strings.Contains(errMsg, "no such file") ||
			strings.Contains(errMsg, "cannot run") {
			return nil, fmt.Errorf("failed to launch browser: %w\nMake sure a Chromium-based browser is installed (Edge, Chrome, Chromium, Brave)", err)
		}
		// Navigation "error" is normal during SSO (ERR_ABORTED, etc.) — browser is still open
		fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] SSO redirect in progress (this is normal)...\n")
	}

	// Poll for SAP cookies until they appear or timeout.
	// Pass the SAP base URL explicitly so GetCookies works even when
	// the browser navigation ended up as a download or redirect.
	cookies, err := pollForSAPCookies(timeoutCtx, sapURL, verbose)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Authentication successful! Extracted %d cookies\n", len(cookies))
	if verbose {
		for name := range cookies {
			fmt.Fprintf(os.Stderr, "[BROWSER-AUTH]   cookie: %s\n", name)
		}
	}

	// Gracefully close the browser via CDP so the window disappears immediately.
	// The deferred cleanupBrowser will handle any remaining process/dir cleanup.
	chromedp.Run(browserCtx, browser.Close())

	return cookies, nil
}

// launchBrowserProcess starts a Chromium browser with DevTools enabled and returns
// the WebSocket debugger URL. The caller is responsible for calling cleanupBrowser.
//
// Instead of reading the DevTools URL from stdout/stderr (which fails under VS Code's
// job object / ConPTY), we:
//  1. Find a free TCP port
//  2. Launch Edge with --remote-debugging-port=PORT
//  3. Poll http://127.0.0.1:PORT/json/version until it responds with the wsURL
//
// This approach is immune to pipe/handle inheritance issues.
func launchBrowserProcess(ctx context.Context, execPath, sapHost string, insecure, verbose bool) (wsURL string, cmd *exec.Cmd, dataDir string, debugPort int, err error) {
	// Create temporary user data directory
	dataDir, err = os.MkdirTemp("", "vsp-browser-*")
	if err != nil {
		return "", nil, "", 0, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Find a free port for DevTools
	debugPort, err = findFreePort()
	if err != nil {
		os.RemoveAll(dataDir)
		return "", nil, "", 0, fmt.Errorf("failed to find free port: %w", err)
	}

	args := []string{
		fmt.Sprintf("--remote-debugging-port=%d", debugPort),
		"--user-data-dir=" + dataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-sync",
		"--disable-breakpad",
		"--disable-background-networking",
		"--disable-component-update",
		"--enable-automation",
		"--password-store=basic",
		"--use-mock-keychain",
		"--window-size=800,700",
		// User-Agent mimics Eclipse ADT so SAP sends Negotiate (Kerberos) auth
		"--user-agent=Eclipse/4.39.0 (win32; x86_64) ADT/3.56.0 (devedition)",
		// Enable Kerberos/SPNEGO with the SAP host
		"--auth-server-whitelist=" + sapHost,
		"--auth-negotiate-delegate-whitelist=" + sapHost,
	}
	if insecure {
		args = append(args, "--ignore-certificate-errors")
	}
	if os.Getuid() == 0 {
		args = append(args, "--no-sandbox")
	}
	// Start with about:blank to avoid opening the user's configured start page.
	// We'll navigate to the real URL via CDP after connecting.
	args = append(args, "about:blank")

	cmd = exec.CommandContext(ctx, execPath, args...)
	setBrowserProcessAttrs(cmd)
	// Redirect all handles away from the MCP protocol pipes
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		os.RemoveAll(dataDir)
		return "", nil, "", 0, fmt.Errorf("failed to start browser: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Launched browser (PID %d) on debug port %d\n", cmd.Process.Pid, debugPort)
	}

	// Poll the DevTools HTTP endpoint until it responds
	wsURL, err = pollDevToolsEndpoint(ctx, debugPort, verbose)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		os.RemoveAll(dataDir)
		return "", nil, "", 0, err
	}

	return wsURL, cmd, dataDir, debugPort, nil
}

// findFreePort asks the OS for a free TCP port by binding to :0.
func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}

// findFirstTarget queries the DevTools HTTP API for the first "page" target.
// This lets us attach to Edge's existing about:blank tab instead of creating a new one.
func findFirstTarget(port int) (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var targets []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &targets); err != nil {
		return "", err
	}

	for _, t := range targets {
		if t.Type == "page" && t.ID != "" {
			return t.ID, nil
		}
	}
	return "", fmt.Errorf("no page targets found")
}

// pollDevToolsEndpoint polls the Chrome DevTools HTTP endpoint until it returns
// the WebSocket debugger URL, or the context/timeout expires.
func pollDevToolsEndpoint(ctx context.Context, port int, verbose bool) (string, error) {
	endpointURL := fmt.Sprintf("http://127.0.0.1:%d/json/version", port)
	client := &http.Client{Timeout: 2 * time.Second}

	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline:
			return "", fmt.Errorf("timed out waiting for browser DevTools on port %d", port)
		case <-ticker.C:
			resp, err := client.Get(endpointURL)
			if err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Waiting for DevTools on port %d...\n", port)
				}
				continue
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			// Parse {"webSocketDebuggerUrl": "ws://127.0.0.1:PORT/devtools/browser/UUID"}
			var result struct {
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				continue
			}
			if result.WebSocketDebuggerURL != "" {
				if verbose {
					fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] DevTools URL: %s\n", result.WebSocketDebuggerURL)
				}
				return result.WebSocketDebuggerURL, nil
			}
		}
	}
}

// cleanupBrowser kills the browser process and removes its temp directory.
func cleanupBrowser(cmd *exec.Cmd, dataDir string) {
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
	if dataDir != "" {
		// Small delay for Windows file locks to be released
		time.Sleep(50 * time.Millisecond)
		os.RemoveAll(dataDir)
	}
}

// pollForSAPCookies polls the browser for SAP-specific cookies at 1-second intervals.
func pollForSAPCookies(ctx context.Context, sapURL string, verbose bool) (map[string]string, error) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	pollCount := 0
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("browser auth timed out — login was not completed in time")
		case <-ticker.C:
			pollCount++
			cookies, found, err := extractSAPCookies(ctx, sapURL)
			if err != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("browser was closed before authentication completed")
				}
				if verbose {
					fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Poll #%d: error reading cookies: %v\n", pollCount, err)
				}
				continue
			}
			if verbose {
				names := make([]string, 0, len(cookies))
				for name := range cookies {
					names = append(names, name)
				}
				fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Poll #%d: %d cookies [%s]\n", pollCount, len(cookies), strings.Join(names, ", "))
			}
			if found {
				return cookies, nil
			}
		}
	}
}

// extractSAPCookies retrieves all cookies from the browser and checks for SAP auth cookies.
func extractSAPCookies(ctx context.Context, sapURL string) (map[string]string, bool, error) {
	var browserCookies []*network.Cookie
	var currentURL string

	// A JSESSIONID can now be set before authentication. Only treat it as a BTP
	// auth cookie after the flow has left the identity provider and callback.
	_ = chromedp.Run(ctx, chromedp.Location(&currentURL))

	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		// Request cookies for the SAP URL explicitly, so they are returned
		// even when the browser page is in a download/redirect state.
		browserCookies, err = network.GetCookies().WithURLs([]string{sapURL}).Do(ctx)
		return err
	})); err != nil {
		return nil, false, err
	}

	result := make(map[string]string)

	for _, c := range browserCookies {
		result[c.Name] = c.Value
	}

	return result, hasSAPAuthCookie(browserCookies, currentURL, sapURL), nil
}

func hasSAPAuthCookie(cookies []*network.Cookie, currentURL, sapURL string) bool {
	for _, cookie := range cookies {
		for _, prefix := range sapAuthCookieNames {
			if strings.HasPrefix(cookie.Name, prefix) {
				return true
			}
		}
	}

	current, currentErr := url.Parse(currentURL)
	sap, sapErr := url.Parse(sapURL)
	if currentErr != nil || sapErr != nil ||
		!strings.EqualFold(current.Host, sap.Host) ||
		strings.HasPrefix(current.Path, "/login/") {
		return false
	}

	for _, cookie := range cookies {
		if strings.HasPrefix(cookie.Name, btpAuthCookieName) {
			return true
		}
	}

	return false
}

// SaveCookiesToFile writes cookies in Netscape cookie file format.
// This allows reuse via --cookie-file on subsequent runs.
func SaveCookiesToFile(cookies map[string]string, sapURL, filePath string) error {
	u, err := url.Parse(sapURL)
	if err != nil {
		return fmt.Errorf("invalid SAP URL: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create cookie file: %w", err)
	}
	defer f.Close()

	fmt.Fprintln(f, "# Netscape HTTP Cookie File")
	fmt.Fprintln(f, "# Generated by vsp --browser-auth")
	fmt.Fprintf(f, "# %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintln(f)

	domain := u.Hostname()
	secure := "FALSE"
	if u.Scheme == "https" {
		secure = "TRUE"
	}

	expiry := time.Now().Add(24 * time.Hour).Unix()

	for name, value := range cookies {
		fmt.Fprintf(f, "%s\tTRUE\t/\t%s\t%d\t%s\t%s\n", domain, secure, expiry, name, value)
	}

	return nil
}
