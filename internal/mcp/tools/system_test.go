package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/oisee/vibing-steampunk/pkg/adt"
)

type mockSystem struct {
	prober *adt.FeatureProber
}

func (m *mockSystem) ADT() *adt.Client { return nil }

func (m *mockSystem) IsRfcMode() bool { return false }

func (m *mockSystem) FeatureProber() *adt.FeatureProber { return m.prober }

func (m *mockSystem) DiscoveredEndpoints() adt.DiscoveredEndpoints { return nil }

func (m *mockSystem) Connect(_ context.Context) error { return nil }

func (m *mockSystem) Start(_ context.Context) error { return nil }

func (m *mockSystem) InitAsync() {}

func (m *mockSystem) EnsureReady(_ context.Context) error { return nil }

func (m *mockSystem) Shutdown() error { return nil }

func TestHandleGetFeatures(t *testing.T) {
	prober := adt.NewFeatureProber(nil, adt.FeatureConfig{
		HANA:      adt.FeatureModeOn,
		AbapGit:   adt.FeatureModeOff,
		RAP:       adt.FeatureModeOn,
		AMDP:      adt.FeatureModeOff,
		UI5:       adt.FeatureModeOn,
		Transport: adt.FeatureModeOff,
	}, false)

	result, err := HandleGetFeatures(context.Background(), &mockSystem{prober: prober}, mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("HandleGetFeatures() returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("HandleGetFeatures() returned nil result")
	}
	if result.IsError {
		t.Fatalf("HandleGetFeatures() returned error result: %+v", result)
	}
	if len(result.Content) != 1 {
		t.Fatalf("HandleGetFeatures() returned %d content items, want 1", len(result.Content))
	}

	text, ok := mcp.AsTextContent(result.Content[0])
	if !ok {
		t.Fatalf("expected text content, got %#v", result.Content[0])
	}

	var payload struct {
		Summary  string `json:"summary"`
		Features map[string]struct {
			Available bool   `json:"available"`
			Mode      string `json:"mode"`
			Message   string `json:"message"`
		} `json:"features"`
	}
	if err := json.Unmarshal([]byte(text.Text), &payload); err != nil {
		t.Fatalf("failed to unmarshal feature payload: %v\ntext=%s", err, text.Text)
	}

	if payload.Summary == "" {
		t.Fatal("expected non-empty feature summary")
	}
	if len(payload.Features) != 6 {
		t.Fatalf("expected 6 features, got %d", len(payload.Features))
	}

	if got := payload.Features["hana"]; !got.Available || got.Mode != string(adt.FeatureModeOn) {
		t.Fatalf("unexpected hana status: %+v", got)
	}
	if got := payload.Features["abapgit"]; got.Available || got.Mode != string(adt.FeatureModeOff) {
		t.Fatalf("unexpected abapgit status: %+v", got)
	}
	if got := payload.Features["connection"]; got.Available || got.Mode != string(adt.FeatureModeOff) {
		t.Fatalf("unexpected connection status: %+v", got)
	}
}
