package api

import (
	"testing"
)

func TestDtoToAction_WebhookConnectorID(t *testing.T) {
	cid := 42
	dto := actionDTO{
		ActionType:   "webhook",
		TriggerPhase: "on_detected",
		RunMode:      "once",
		ConnectorID:  &cid,
	}
	act := dtoToAction(dto, 1)
	if act.WebhookConnectorID == nil || *act.WebhookConnectorID != 42 {
		t.Errorf("webhook: WebhookConnectorID = %v, want ptr(42)", act.WebhookConnectorID)
	}
	if act.ShellConnectorID != nil {
		t.Errorf("webhook: ShellConnectorID should be nil, got %v", act.ShellConnectorID)
	}
}

func TestDtoToAction_ShellConnectorID(t *testing.T) {
	cid := 7
	dto := actionDTO{
		ActionType:   "shell",
		TriggerPhase: "on_detected",
		RunMode:      "once",
		ConnectorID:  &cid,
	}
	act := dtoToAction(dto, 1)
	if act.ShellConnectorID == nil || *act.ShellConnectorID != 7 {
		t.Errorf("shell: ShellConnectorID = %v, want ptr(7)", act.ShellConnectorID)
	}
	if act.WebhookConnectorID != nil {
		t.Errorf("shell: WebhookConnectorID should be nil, got %v", act.WebhookConnectorID)
	}
}

func TestDtoToAction_XDropNoFKs(t *testing.T) {
	cid := 99
	dto := actionDTO{
		ActionType:   "xdrop",
		TriggerPhase: "on_detected",
		RunMode:      "once",
		ConnectorID:  &cid,
	}
	act := dtoToAction(dto, 1)
	if act.WebhookConnectorID != nil {
		t.Errorf("xdrop: WebhookConnectorID should be nil, got %v", act.WebhookConnectorID)
	}
	if act.ShellConnectorID != nil {
		t.Errorf("xdrop: ShellConnectorID should be nil, got %v", act.ShellConnectorID)
	}
}

func TestDtoToAction_LegacyPolicyMapping(t *testing.T) {
	tests := []struct {
		name         string
		triggerPhase string
		runMode      string
		wantPolicy   string
	}{
		{"on_detected+once", "on_detected", "once", "once_on_enter"},
		{"on_expired+once", "on_expired", "once", "once_on_exit"},
		{"periodic", "on_detected", "periodic", "periodic"},
		{"retry_until_success", "on_detected", "retry_until_success", "retry_until_success"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dto := actionDTO{
				ActionType:   "webhook",
				TriggerPhase: tt.triggerPhase,
				RunMode:      tt.runMode,
			}
			act := dtoToAction(dto, 1)
			if act.ExecutionPolicy != tt.wantPolicy {
				t.Errorf("ExecutionPolicy = %q, want %q", act.ExecutionPolicy, tt.wantPolicy)
			}
		})
	}
}

func TestDtoToAction_EnabledNilDefaultsTrue(t *testing.T) {
	dto := actionDTO{
		ActionType:   "webhook",
		TriggerPhase: "on_detected",
		RunMode:      "once",
		Enabled:      nil,
	}
	act := dtoToAction(dto, 1)
	if !act.Enabled {
		t.Error("Enabled should default to true when nil")
	}
}

func TestDtoToAction_EnabledFalseStays(t *testing.T) {
	f := false
	dto := actionDTO{
		ActionType:   "webhook",
		TriggerPhase: "on_detected",
		RunMode:      "once",
		Enabled:      &f,
	}
	act := dtoToAction(dto, 1)
	if act.Enabled {
		t.Error("Enabled should be false when explicitly set to false")
	}
}
