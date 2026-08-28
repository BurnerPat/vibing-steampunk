package types

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/oisee/vibing-steampunk/pkg/adt"
)

// System defines the interface for interacting with a single SAP system.
// Systems follow an explicit lifecycle: Connect validates credentials and opens connection,
// Start activates runtime behavior (e.g., keep-alive), and Shutdown cleans up resources.
// Handlers assume the system has been connected before use.
type System interface {
	// ADT returns the ADT client for the system.
	ADT() *adt.Client

	// IsRfcMode returns true if the system is using RFC/JCo sidecar.
	IsRfcMode() bool

	// FeatureProber returns the feature prober for optional-capability detection.
	FeatureProber() *adt.FeatureProber

	// DiscoveredEndpoints returns the ADT endpoints discovered from /sap/bc/adt/discovery.
	// Returns nil if discovery was not performed (e.g., RFC mode or discovery failed).
	DiscoveredEndpoints() adt.DiscoveredEndpoints

	// Connect validates credentials and establishes the connection connection.
	// For HTTP mode, this performs an explicit authentication check (Ping).
	// For RFC/SNC mode, this is a silent no-op as logon validation is deferred to first RFC call.
	// Connect is idempotent and safe to call multiple times.
	// Returns error if authentication or connection fails.
	Connect(ctx context.Context) error

	// Start activates runtime behavior such as session keep-alive.
	// For RFC/SNC mode, this is a silent no-op as runtime management is handled by sidecar or deferred.
	// Start should be called after Connect.
	// Returns error if runtime activation fails.
	Start(ctx context.Context) error

	// InitAsync starts background initialization for the system: JCo sidecar
	// startup (RFC mode), endpoint discovery (Connect) and runtime activation
	// (Start). It is non-blocking and idempotent; the first call kicks off the
	// work, later calls are no-ops. Handlers must call EnsureReady before use.
	InitAsync()

	// EnsureReady blocks until background initialization started by InitAsync has
	// completed, or until ctx is cancelled. It returns the initialization error,
	// if any. Safe to call concurrently and repeatedly.
	EnsureReady(ctx context.Context) error

	// Shutdown gracefully stops system resources (keep-alive, sidecar).
	// Shutdown is idempotent and safe to call multiple times.
	Shutdown() error
}

// ToolHandlerFunc is the signature for MCP tool handlers.
type ToolHandlerFunc func(ctx context.Context, sys System, request mcp.CallToolRequest) (*mcp.CallToolResult, error)

// ParamMapper transforms universal-mode params into handler-specific params.
type ParamMapper func(objectType, objectName string, params map[string]any) map[string]any

// UniversalRoute describes how a tool is accessible via the single SAP(action, target, params) tool.
type UniversalRoute struct {
	Action     string      // universal-mode action: "read", "edit", "create", "delete", "search", "query", "grep", "test", "analyze", "debug", "system"
	TargetType string      // match objectType from target (e.g., "PROG", "INFO"). Empty = don't match on targetType.
	ParamsType string      // match params["type"] (e.g., "list_transports"). Empty = don't match on params.type.
	MapArgs    ParamMapper // optional: transform params before calling handler. nil = pass through.
}

// ToolDef is a self-contained, declarative tool definition.
type ToolDef struct {
	Tool     mcp.Tool
	Handler  ToolHandlerFunc
	AlwaysOn bool     // if true, registered regardless of mode/groups/config
	ReadOnly bool     // tool only reads data, never modifies the SAP system
	Focused  bool     // included in "focused" mode (default mode)
	Groups   []string // group codes for --disabled-groups (e.g., "D", "H", "X")

	// Endpoints lists the ADT endpoint base paths required by this tool.
	// Used for discovery-based filtering: if the SAP system does not advertise
	// a required endpoint in /sap/bc/adt/discovery, the tool is disabled.
	// Tools with an empty Endpoints slice are never filtered by discovery.
	Endpoints []string

	// Universal mode routing (optional).
	Routes []UniversalRoute
}

// ErrorResult is a helper to create an MCP error result.
func ErrorResult(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent(message),
		},
		IsError: true,
	}
}
