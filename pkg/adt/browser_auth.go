package adt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

const systemInformationRelation = "http://www.sap.com/adt/categories/core/http/system/systeminformation"

const sessionInformationAccept = "application/vnd.sap.adt.core.http.session.v3+xml, application/vnd.sap.adt.core.http.session.v2+xml, application/vnd.sap.adt.core.http.session.v1+xml"

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

// BrowserLogin opens the SAP reentrance-ticket flow in the system browser,
// waits for its loopback callback, and returns the resulting session cookies.
//
// Set execPath to use the legacy automated Chromium flow instead. That fallback
// launches the process manually and connects via RemoteAllocator to avoid a known
// ExecAllocator process-exit race in MCP host environments.
func BrowserLogin(ctx context.Context, sapURL string, insecure bool, timeout time.Duration, execPath string, verbose bool) (map[string]string, error) {
	return BrowserLoginWithTarget(ctx, sapURL, "", insecure, timeout, execPath, verbose)
}

// BrowserLoginWithTarget behaves like BrowserLogin. A target override requires
// the automated Chromium flow because arbitrary targets cannot issue callbacks.
func BrowserLoginWithTarget(ctx context.Context, sapURL, targetOverride string, insecure bool, timeout time.Duration, execPath string, verbose bool) (map[string]string, error) {
	return BrowserLoginWithTargetForClient(ctx, sapURL, targetOverride, "", "", insecure, timeout, execPath, verbose)
}

// BrowserLoginWithTargetForClient includes the SAP client and language in the
// native browser preflight, matching the login flow used by Eclipse ADT.
func BrowserLoginWithTargetForClient(ctx context.Context, sapURL, targetOverride, client, language string, insecure bool, timeout time.Duration, execPath string, verbose bool) (map[string]string, error) {
	u, err := url.Parse(sapURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SAP URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid SAP URL (missing scheme or host): %s", sapURL)
	}
	if execPath == "" && strings.TrimSpace(targetOverride) == "" {
		return nativeBrowserLogin(ctx, sapURL, client, language, insecure, timeout, verbose)
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
	wsURL, cmd, debugPort, err := launchBrowserProcess(ctx, execPath, u.Host, insecure, verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to launch %s: %w", browserName, err)
	}
	defer cleanupBrowser(cmd)

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

func nativeBrowserLogin(ctx context.Context, sapURL, client, language string, insecure bool, timeout time.Duration, verbose bool) (map[string]string, error) {
	apiURL, uiURL, err := resolveSystemURLs(ctx, sapURL, insecure)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start browser auth callback: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://localhost:%d/adt/redirect", port)
	ticketResult := make(chan string, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/adt/redirect", func(w http.ResponseWriter, req *http.Request) {
		ticket := strings.TrimSpace(req.URL.Query().Get("reentrance-ticket"))
		if ticket == "" {
			http.Error(w, "Missing reentrance ticket", http.StatusBadRequest)
			return
		}
		select {
		case ticketResult <- ticket:
		default:
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>VSP authentication</title><p>Authentication received. You can close this tab.</p>")
	})

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(serveDone)
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		<-serveDone
	}()

	loginURL, err := buildReentranceTicketURL(uiURL, callbackURL)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Opening the system browser for SSO login: %s\n", uiURL)
	fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Complete login in the browser window. Timeout: %s\n", timeout)
	if err := openSystemBrowser(loginURL); err != nil {
		return nil, fmt.Errorf("failed to open system browser: %w", err)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case ticket := <-ticketResult:
		cookies, err := exchangeReentranceTicket(timeoutCtx, apiURL, ticket, client, language, insecure)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Authentication successful! Extracted %d cookies\n", len(cookies))
		if verbose {
			for name := range cookies {
				fmt.Fprintf(os.Stderr, "[BROWSER-AUTH]   cookie: %s\n", name)
			}
		}
		return cookies, nil
	case <-timeoutCtx.Done():
		return nil, fmt.Errorf("browser auth timed out after %s — login was not completed", timeout)
	}
}

// ResolveBrowserAuthAPIURL returns the API base URL used for ADT requests.
// Cloud systems can expose a separate UI URL for browser authentication.
func ResolveBrowserAuthAPIURL(ctx context.Context, sapURL string, insecure bool) (string, error) {
	apiURL, _, err := resolveSystemURLs(ctx, sapURL, insecure)
	return apiURL, err
}

func resolveSystemURLs(ctx context.Context, sapURL string, insecure bool) (string, string, error) {
	baseURL := strings.TrimRight(sapURL, "/")
	endpoint := strings.TrimRight(sapURL, "/") + "/sap/public/bc/icf/virtualhost"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create SAP host discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: insecure, //nolint:gosec
	}}}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to discover SAP system URLs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented {
		return baseURL, baseURL, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("SAP host discovery failed: HTTP %s", resp.Status)
	}

	var hostInfo struct {
		RelatedURLs struct {
			API string `json:"API"`
			UI  string `json:"UI"`
		} `json:"relatedUrls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hostInfo); err != nil {
		return "", "", fmt.Errorf("invalid SAP host discovery response: %w", err)
	}
	apiURL, err := normalizeDiscoveredBaseURL(hostInfo.RelatedURLs.API)
	if err != nil {
		return "", "", fmt.Errorf("invalid SAP API URL in host discovery response: %q", hostInfo.RelatedURLs.API)
	}
	uiURL, err := normalizeDiscoveredBaseURL(hostInfo.RelatedURLs.UI)
	if err != nil {
		return "", "", fmt.Errorf("invalid SAP UI URL in host discovery response: %q", hostInfo.RelatedURLs.UI)
	}
	return apiURL, uiURL, nil
}

func normalizeDiscoveredBaseURL(rawURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid URL")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func buildReentranceTicketURL(sapURL, callbackURL string) (string, error) {
	base, err := url.Parse(strings.TrimRight(sapURL, "/") + "/sap/bc/adt/core/http/reentranceticket")
	if err != nil {
		return "", fmt.Errorf("invalid SAP URL: %w", err)
	}
	query := base.Query()
	query.Set("redirect-url", callbackURL)
	query.Set("_", fmt.Sprintf("%d", time.Now().UnixMilli()))
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func openSystemBrowser(targetURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", targetURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	return cmd.Run()
}

func exchangeReentranceTicket(ctx context.Context, sapURL, ticket, client, language string, insecure bool) (map[string]string, error) {
	sessionsURL, err := url.Parse(strings.TrimRight(sapURL, "/") + "/sap/bc/adt/core/http/sessions")
	if err != nil {
		return nil, fmt.Errorf("invalid SAP URL: %w", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser auth cookie jar: %w", err)
	}
	httpClient := &http.Client{
		Jar: jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, //nolint:gosec
		}},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sessionsURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create reentrance ticket request: %w", err)
	}
	req.Header.Set("MYSAPSSO2", ticket)
	req.Header.Set("Accept", sessionInformationAccept)
	req.Header.Set("User-Agent", "Eclipse/4.39.0 (win32; x86_64) ADT/3.56.0 (devedition)")
	req.Header.Set("sap-adt-purpose", "preflight_logon")
	req.Header.Set("x-sap-security-session", "create")
	if client != "" {
		req.Header.Set("sap-client", client)
	}
	if language != "" {
		req.Header.Set("sap-language", language)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange reentrance ticket: %w", err)
	}
	defer resp.Body.Close()
	sessionBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read reentrance ticket response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("reentrance ticket exchange failed: HTTP %s", resp.Status)
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/html") || strings.Contains(strings.ToLower(string(sessionBody[:min(len(sessionBody), 200)])), "<html") {
		return nil, fmt.Errorf("reentrance ticket was not accepted by the ADT sessions endpoint")
	}

	systemInfoURL, accept, err := parseSystemInformationLink(sapURL, sessionBody)
	if err != nil {
		return nil, err
	}
	systemInfoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, systemInfoURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create system information request: %w", err)
	}
	systemInfoReq.Header.Set("Accept", accept)
	systemInfoReq.Header.Set("User-Agent", "Eclipse/4.39.0 (win32; x86_64) ADT/3.56.0 (devedition)")
	systemInfoReq.Header.Set("x-sap-security-session", "use")
	systemInfoResp, err := httpClient.Do(systemInfoReq)
	if err != nil {
		return nil, fmt.Errorf("failed to complete browser authentication: %w", err)
	}
	defer systemInfoResp.Body.Close()
	_, _ = io.Copy(io.Discard, systemInfoResp.Body)
	if systemInfoResp.StatusCode < 200 || systemInfoResp.StatusCode >= 300 {
		return nil, fmt.Errorf("browser authentication preflight failed: HTTP %s", systemInfoResp.Status)
	}

	discoveryURL, err := url.Parse(strings.TrimRight(sapURL, "/") + "/sap/bc/adt/core/discovery")
	if err != nil {
		return nil, fmt.Errorf("invalid SAP URL: %w", err)
	}

	cookies := make(map[string]string)
	for _, cookie := range jar.Cookies(discoveryURL) {
		cookies[cookie.Name] = cookie.Value
	}
	if !hasSAPSessionCookie(cookies) {
		return nil, fmt.Errorf("reentrance ticket exchange returned no SAP session cookie")
	}
	return cookies, nil
}

func parseSystemInformationLink(sapURL string, body []byte) (*url.URL, string, error) {
	var document struct {
		Links []struct {
			Relation string `xml:"rel,attr"`
			Href     string `xml:"href,attr"`
			Type     string `xml:"type,attr"`
		} `xml:"link"`
	}
	if err := xml.Unmarshal(body, &document); err != nil {
		return nil, "", fmt.Errorf("invalid browser authentication session response: %w", err)
	}
	for _, link := range document.Links {
		if link.Relation != systemInformationRelation || link.Href == "" {
			continue
		}
		base, err := url.Parse(strings.TrimRight(sapURL, "/") + "/")
		if err != nil {
			return nil, "", fmt.Errorf("invalid SAP URL: %w", err)
		}
		href, err := url.Parse(link.Href)
		if err != nil {
			return nil, "", fmt.Errorf("invalid system information URL: %w", err)
		}
		accept := link.Type
		if accept == "" {
			accept = "application/xml"
		}
		return base.ResolveReference(href), accept, nil
	}
	return nil, "", fmt.Errorf("browser authentication session response has no system information link")
}

func hasSAPSessionCookie(cookies map[string]string) bool {
	for name := range cookies {
		if strings.HasPrefix(name, btpAuthCookieName) {
			return true
		}
		for _, prefix := range sapAuthCookieNames {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	}
	return false
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
func launchBrowserProcess(ctx context.Context, execPath, sapHost string, insecure, verbose bool) (wsURL string, cmd *exec.Cmd, debugPort int, err error) {
	dataDir, err := browserDataDir(execPath)
	if err != nil {
		return "", nil, 0, fmt.Errorf("failed to create browser profile: %w", err)
	}

	// Find a free port for DevTools
	debugPort, err = findFreePort()
	if err != nil {
		return "", nil, 0, fmt.Errorf("failed to find free port: %w", err)
	}

	args := buildBrowserProcessArgs(debugPort, dataDir, sapHost, insecure)
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
		return "", nil, 0, fmt.Errorf("failed to start browser: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[BROWSER-AUTH] Launched browser (PID %d) on debug port %d\n", cmd.Process.Pid, debugPort)
	}

	// Poll the DevTools HTTP endpoint until it responds
	wsURL, err = pollDevToolsEndpoint(ctx, debugPort, verbose)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return "", nil, 0, err
	}

	return wsURL, cmd, debugPort, nil
}

func browserDataDir(execPath string) (string, error) {
	if override := strings.TrimSpace(os.Getenv("VSP_BROWSER_DATA_DIR")); override != "" {
		if err := os.MkdirAll(override, 0700); err != nil {
			return "", err
		}
		return override, nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	browserID := strings.ToLower(strings.ReplaceAll(friendlyBrowserName(execPath), " ", "-"))
	dataDir := filepath.Join(configDir, "vsp", "browser-auth", browserID)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", err
	}
	return dataDir, nil
}

func buildBrowserProcessArgs(debugPort int, dataDir, sapHost string, insecure bool) []string {
	args := []string{
		fmt.Sprintf("--remote-debugging-port=%d", debugPort),
		"--user-data-dir=" + dataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-default-apps",
		"--disable-breakpad",
		"--disable-component-update",
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
	return args
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

// cleanupBrowser kills the browser process. Its profile remains available for
// future logins so Edge can retain account sync and password-manager data.
func cleanupBrowser(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		<-done
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
