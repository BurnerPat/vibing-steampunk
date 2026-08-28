// Package internal provides internal infrastructure for vsp.
package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"

	"dario.cat/mergo"
	"github.com/oisee/vibing-steampunk/internal/config"
	"github.com/oisee/vibing-steampunk/pkg/adt"
	"github.com/spf13/cobra"
)

// Bootstrap orchestrates the entire configuration pipeline:
// 1. Viper/Cobra have already resolved CLI flags and environment variables into cfg
// 2. Load configuration file (.vsp.json) if available
// 3. Merge config file into cfg with precedence: CLI/Env wins > Config File
// 4. Augment configuration with derived data (SNC, JCo properties, cookies, etc.)
// 5. Validate final configuration
// 6. Return fully-prepared config ready for mcp.NewServer()
//
// Parameters:
//   - cfg: Base config structure (already populated by Viper/Cobra from CLI/ENV)
//   - singleSys: Per-system settings from CLI/ENV (already populated)
//   - multiSystem: Whether multi-system mode is enabled
//   - configFile: Explicit path to .vsp.json (empty = auto-discover)
//   - systemName: System name from --system flag (for single-system mode)
//   - cmd: Cobra command for flag inspection
//
// Returns the fully-augmented ResolvedConfig ready for instantiation.
func Bootstrap(cfg *config.GlobalConfig, singleSys *config.SystemConfig, multiSystem bool, configFile, systemName string, cmd *cobra.Command) (*config.GlobalConfig, error) {
	// Step 1: Load configuration file (.vsp.json) if available
	// Config file is OPTIONAL - if not found, just continue with CLI/ENV config
	var configurationFromFile *config.GlobalConfig
	var configurationFilePath string

	if configFile != "" {
		var err error
		configurationFromFile, err = config.LoadConfigurationFromFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", configFile, err)
		}
		configurationFilePath = configFile
	} else {
		var err error
		configurationFromFile, configurationFilePath, err = config.LoadConfiguration()
		if err != nil {
			// Config file not found - that's OK, continue with CLI/ENV config
			if cfg.Verbose {
				_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] No config file found, using CLI/ENV configuration\n")
			}
		}
	}

	// Apply tool visibility from .vsp.json (if it exists)
	if configurationFromFile != nil {
		err := mergeConfiguration(cfg, configurationFromFile)

		if err != nil {
			return nil, fmt.Errorf("failed to merge configuration: %w", err)
		}

		if cfg.Verbose {
			_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] Config loaded from %s\n", configurationFilePath)
		}
	}

	// Step 2: Route to multi-system or single-system bootstrap
	if multiSystem {
		if err := bootstrapMultiSystem(cfg, configurationFilePath); err != nil {
			return nil, err
		}
	} else {
		if err := bootstrapSingleSystem(cfg, singleSys, systemName); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// bootstrapMultiSystem populates cfg.Systems from .vsp.json and augments each system.
func bootstrapMultiSystem(cfg *config.GlobalConfig, systemsConfigPath string) error {
	if systemsConfigPath == "" {
		return fmt.Errorf("--multi-system requires a .vsp.json configuration file. Use --config to specify path or create one with 'vsp config init'")
	}

	if len(cfg.Systems) == 0 {
		return fmt.Errorf("--multi-system: no systems defined in configuration file %s", systemsConfigPath)
	}

	rfcSystemCount := 0
	activeSystems := make(map[string]config.SystemConfig, len(cfg.Systems))

	for sysID, sysDef := range cfg.Systems {
		if sysDef.Disabled {
			if cfg.Verbose {
				_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] Multi-system: skipping disabled system %q\n", sysID)
			}
			continue
		}

		// GetSystem returns *config.SystemConfig directly — no conversion needed
		err := fillSystemLogonDataFromEnvOrConfig(sysID, &sysDef)

		if err != nil {
			return fmt.Errorf("--multi-system: failed to resolve system %q: %w", sysID, err)
		}

		if err := augmentSystemConfiguration(&sysDef, cfg); err != nil {
			return fmt.Errorf("--multi-system: failed to augment system %q: %w", sysID, err)
		}

		// Count RFC systems (explicit or via SNC)
		if strings.EqualFold(sysDef.ConnectionMode, "rfc") {
			rfcSystemCount++
		}

		activeSystems[sysID] = sysDef
	}

	cfg.Systems = activeSystems

	if rfcSystemCount > 1 && cfg.Verbose {
		_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] Multi-system: %d RFC systems detected, using stdio sidecar connection\n", rfcSystemCount)
	}

	if cfg.Verbose {
		_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] Multi-system mode: %d systems loaded from %s\n", len(cfg.Systems), systemsConfigPath)

		for id := range cfg.Systems {
			_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE]   - %s\n", id)
		}
	}

	return nil
}

// bootstrapSingleSystem resolves single-system configuration from CLI/ENV and .vsp.json profile.
func bootstrapSingleSystem(cfg *config.GlobalConfig, singleSys *config.SystemConfig, systemName string) error {
	// If --system flag is specified, load system config from .vsp.json first
	// System profile values act as base defaults; CLI/ENV values override them via merging
	if systemName != "" {
		// GetSystem returns *config.SystemConfig directly — no conversion needed
		err := fillSystemLogonDataFromEnvOrConfig(systemName, singleSys)

		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[WARN] %v\n", err)
		}
	}

	// Validate single-system configuration
	if err := validateSystemConfiguration(singleSys, cfg); err != nil {
		return err
	}

	// Augment the system configuration (SNC, RFC, cookies, auth, etc.)
	if err := augmentSystemConfiguration(singleSys, cfg); err != nil {
		return err
	}

	cfg.Systems = make(map[string]config.SystemConfig)
	cfg.Systems[config.DefaultSystemID] = *singleSys

	return nil
}

// mergeSystemConfiguration merges fileConfig into cliEnv with CLI/ENV taking precedence.
// Uses mergo: zero-value fields in cliEnv are filled from fileConfig; non-zero fields are kept.
func mergeConfiguration(globalConfig *config.GlobalConfig, fileConfig *config.GlobalConfig) error {
	if err := mergo.Merge(globalConfig, fileConfig); err != nil {
		return fmt.Errorf("failed to merge system configuration: %w", err)
	}

	return nil
}

// augmentSystemConfiguration augments a system with derived runtime data:
// SNC/JCo properties from SAP UI Landscape, and cookie authentication.
func augmentSystemConfiguration(sys *config.SystemConfig, globalCfg *config.GlobalConfig) error {
	// Resolve SNC/SSO configuration from SAP UI Landscape file
	if sys.SNC {
		if sys.SysID == "" {
			return fmt.Errorf("--sysid is required when --snc is specified")
		}
		// Per-system landscape file takes precedence; otherwise fall back to the
		// global --landscape-file flag (which is ignored in multi-system mode
		// unless applied here, since singleSys is discarded).
		landscapeFile := sys.LandscapeFile
		if landscapeFile == "" {
			landscapeFile = globalCfg.LandscapeFile
		}
		if globalCfg.Verbose {
			_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] SNC mode: resolving system %q from SAP UI Landscape\n", sys.SysID)
			if landscapeFile != "" {
				_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] Using landscape file: %s\n", landscapeFile)
			}
		}
		jcoProps, err := adt.ResolveSNCJcoProperties(sys.SysID, landscapeFile, sys.Client, sys.Language)
		if err != nil {
			return fmt.Errorf("SNC configuration failed: %w", err)
		}
		sys.JcoProperties = jcoProps
		sys.ConnectionMode = "rfc" // SNC requires RFC mode via JCo sidecar
		if globalCfg.Verbose {
			_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE] SNC: resolved %d JCo properties for system %q\n", len(jcoProps), sys.SysID)
			for k, v := range jcoProps {
				_, _ = fmt.Fprintf(os.Stderr, "[VERBOSE]   %s = %s\n", k, v)
			}
		}
	}

	return nil
}

// resolveOSUsername returns the current OS login name, uppercased to match
// SAP conventions. On Windows, any DOMAIN\user prefix is stripped.
// Returns an empty string if the lookup fails (non-fatal).
func resolveOSUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	// Windows may return DOMAIN\user — strip the domain prefix
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToUpper(name)
}

// GetSystem retrieves a system configuration by name, resolving password from env.
func fillSystemLogonDataFromEnvOrConfig(name string, sys *config.SystemConfig) error {
	if sys.Disabled {
		return fmt.Errorf("system '%s' is disabled", name)
	}

	// Resolve password from environment variable if not set
	if sys.Password == "" {
		// Try VSP_<SYSTEM>_PASSWORD (e.g., VSP_A4H_PASSWORD)
		envKey := fmt.Sprintf("VSP_%s_PASSWORD", strings.ToUpper(name))
		if pwd := os.Getenv(envKey); pwd != "" {
			sys.Password = pwd
		}
	}

	// Fallback: resolve password from .mcp.json env block
	if sys.Password == "" {
		envKey := fmt.Sprintf("VSP_%s_PASSWORD", strings.ToUpper(name))
		if pwd := loadMcpEnvVar(envKey); pwd != "" {
			sys.Password = pwd
		}
	}

	// Apply defaults
	if sys.Client == "" {
		sys.Client = "001"
	}

	if sys.Language == "" {
		sys.Language = "EN"
	}

	// Default username to OS login name if not set by any source.
	// Skip when using browser-based or cookie-based auth (no username needed).
	if sys.Username == "" && !sys.BrowserAuth && sys.CookieFile == "" && sys.CookieString == "" {
		if osUser := resolveOSUsername(); osUser != "" {
			sys.Username = osUser
		}
	}

	return nil
}

// mcpConfig represents the structure of .mcp.json for env var extraction.
type mcpConfig struct {
	McpServers map[string]struct {
		Env map[string]string `json:"env"`
	} `json:"mcpServers"`
}

// loadMcpEnvVar searches .mcp.json env blocks for a given variable name.
func loadMcpEnvVar(key string) string {
	for _, path := range []string{".mcp.json"} {
		data, err := os.ReadFile(path)

		if err != nil {
			continue
		}

		var cfg mcpConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}

		for _, server := range cfg.McpServers {
			if val, ok := server.Env[key]; ok {
				return val
			}
		}
	}
	return ""
}

// validateSystemConfiguration validates a system configuration for consistency.
func validateSystemConfiguration(sys *config.SystemConfig, globalCfg *config.GlobalConfig) error {
	// In RFC mode, URL is not required; RFC connection params are
	if strings.EqualFold(sys.ConnectionMode, "rfc") {
		if sys.SNC {
			// SNC mode: connection params come from JcoProperties (resolved from landscape)
			if len(sys.JcoProperties) == 0 {
				return fmt.Errorf("SNC mode enabled but no JCo properties resolved from landscape")
			}
		} else {
			// Standard RFC mode: need explicit connection params
			hasDirect := sys.AsHost != ""
			hasLB := sys.MsHost != ""
			if !hasDirect && !hasLB {
				return fmt.Errorf("RFC mode requires --ashost or --mshost")
			}
			if hasDirect && hasLB {
				return fmt.Errorf("cannot specify both --ashost (direct) and --mshost (load balancing)")
			}
			if hasDirect && sys.SysNr == "" {
				return fmt.Errorf("--sysnr required for direct RFC connection")
			}
			if hasLB {
				if sys.MsServ == "" {
					return fmt.Errorf("--msserv required for RFC load balancing")
				}
				if sys.R3Name == "" {
					return fmt.Errorf("--r3name required for RFC load balancing")
				}
				if sys.Group == "" {
					return fmt.Errorf("--group required for RFC load balancing")
				}
			}
		}
	} else {
		// HTTP mode requires URL
		if sys.URL == "" {
			return fmt.Errorf("SAP URL is required. Use --url flag or SAP_URL environment variable")
		}
	}

	// Validate mode
	if globalCfg.Mode != "focused" && globalCfg.Mode != "expert" && globalCfg.Mode != "hyperfocused" {
		return fmt.Errorf("invalid mode: %s (must be 'focused', 'expert', or 'hyperfocused')", globalCfg.Mode)
	}

	return nil
}
