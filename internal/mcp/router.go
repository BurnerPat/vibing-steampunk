package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/oisee/vibing-steampunk/internal/config"
	"github.com/oisee/vibing-steampunk/internal/mcp/tools"
	"github.com/oisee/vibing-steampunk/internal/mcp/types"
)

// Router handles tool call routing and system management.
type Router struct {
	mcpServer         *server.MCPServer
	systems           map[string]types.System // keyed by lowercase system ID
	systemIDs         []string                // original-cased IDs in insertion order
	allTools          []types.ToolDef
	permissionManager *PermissionManager
}

func NewRouter(mcpServer *server.MCPServer) *Router {
	return &Router{
		mcpServer: mcpServer,
		systems:   make(map[string]types.System),
	}
}

func (r *Router) AddSystem(id string, sys types.System) {
	r.systems[strings.ToLower(id)] = sys
	r.systemIDs = append(r.systemIDs, id)
}

// RegisterTools registers all available tools from all packages.
func (r *Router) RegisterTools(cfg *config.GlobalConfig, systems map[string]types.System) {
	var err error
	r.permissionManager, err = NewPermissionManager(cfg, tools.AllToolDefs())
	if err != nil {
		panic(err)
	}

	r.allTools = tools.AllToolDefs()

	// Apply endpoint-based filtering using ADT discovery results.
	// This runs after permission-based filtering (inside NewPermissionManager)
	// and further reduces the enabled tool set per system.
	r.permissionManager.ApplyEndpointFilter(systems, cfg.Verbose)

	r.permissionManager.LogEffectivePermissions()

	// Register each globally-enabled tool once with a central handler
	for _, td := range r.permissionManager.GetGloballyEnabledTools() {
		tool := td.Tool
		if len(r.systemIDs) > 1 {
			tool = r.addSystemIDToTool(tool)
		}

		toolDef := td
		r.mcpServer.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return r.HandleToolCall(ctx, toolDef, request)
		})
	}

	// Discovery meta-tools (always available, bypass permission pipeline)
	r.registerDiscoveryTools()
}

func (r *Router) HandleToolCall(ctx context.Context, td *types.ToolDef, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. Determine target system
	systemID, _ := request.GetArguments()["system_id"].(string)

	if systemID == "" && len(r.systemIDs) == 1 {
		systemID = r.systemIDs[0]
	}

	if systemID == "" {
		return types.ErrorResult(fmt.Sprintf("system_id is required. Available: %s", strings.Join(r.systemIDs, ", "))), nil
	}

	sys, ok := r.systems[strings.ToLower(systemID)]
	if !ok {
		return types.ErrorResult(fmt.Sprintf("Unknown system: %s. Available: %s", systemID, strings.Join(r.systemIDs, ", "))), nil
	}

	// 1b. Wait for the target system to finish background initialization
	//     (JCo sidecar startup + endpoint discovery). The first call after the
	//     server starts may block here until the system is ready.
	if err := sys.EnsureReady(ctx); err != nil {
		return types.ErrorResult(fmt.Sprintf("System %q failed to initialize: %v", systemID, err)), nil
	}

	// 2. Permission check (tool-level)
	if !r.permissionManager.IsToolEnabledForSystem(systemID, td.Tool.Name) {
		enabledTools := r.permissionManager.GetEnabledToolsForSystem(systemID)
		return types.ErrorResult(r.permissionDeniedMessage(td.Tool.Name, systemID, enabledTools)), nil
	}

	// 3. Object-level permission check
	objectName := extractObjectName(request)
	if objectName != "" {
		objectPackage, _ := request.GetArguments()["package"].(string)
		if err := r.permissionManager.IsObjectAllowedForTool(systemID, td.Tool.Name, objectName, objectPackage); err != nil {
			return types.ErrorResult(err.Error()), nil
		}
	}

	// 4. Invoke handler
	return td.Handler(ctx, sys, request)
}

// extractObjectName tries to extract the object name from request arguments.
// It checks common parameter names used by SAP ADT tools.
func extractObjectName(request mcp.CallToolRequest) string {
	args := request.GetArguments()

	for _, key := range []string{"object_name", "name", "table_name", "table", "class_name", "program_name", "object"} {
		if v, ok := args[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func (r *Router) addSystemIDToTool(tool mcp.Tool) mcp.Tool {
	if tool.InputSchema.Properties == nil {
		tool.InputSchema.Properties = make(map[string]interface{})
	}

	newProps := make(map[string]interface{})
	for k, v := range tool.InputSchema.Properties {
		newProps[k] = v
	}

	newProps["system_id"] = map[string]interface{}{
		"type":        "string",
		"description": fmt.Sprintf("Target SAP system ID. Available: %s", strings.Join(r.systemIDs, ", ")),
		"enum":        r.systemIDs,
	}

	tool.InputSchema.Properties = newProps
	tool.InputSchema.Required = append(tool.InputSchema.Required, "system_id")

	return tool
}

const maxToolsInError = 10

func (r *Router) permissionDeniedMessage(toolName, systemID string, enabledTools []*types.ToolDef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Permission denied for tool %s on system %s.", toolName, systemID)

	if len(enabledTools) == 0 {
		b.WriteString(" No tools are enabled on this system.")
		return b.String()
	}

	b.WriteString(" Available tools: ")
	limit := min(len(enabledTools), maxToolsInError)

	for i := 0; i < limit; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(enabledTools[i].Tool.Name)
	}

	if len(enabledTools) > maxToolsInError {
		fmt.Fprintf(&b, " (and %d more — use ListAvailableTools for full list)", len(enabledTools)-maxToolsInError)
	}

	return b.String()
}
