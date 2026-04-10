package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// executeShell executes a shell action using the configured ShellConnector.
func executeShell(
	ctx context.Context,
	s store.Store,
	action store.ResponseAction,
	attack *store.Attack,
	eventType string,
	prefixStr string,
	responseName string,
	triggerPhase string,
	attackDBID int,
	fa *FlowAnalysis,
) (*store.ActionExecutionLog, error) {
	if action.ShellConnectorID == nil {
		return nil, fmt.Errorf("shell action %d has no shell_connector_id", action.ID)
	}

	connector, err := s.ShellConnectors().Get(ctx, *action.ShellConnectorID)
	if err != nil {
		return nil, fmt.Errorf("get shell connector %d: %w", *action.ShellConnectorID, err)
	}
	if !connector.Enabled {
		execLog := &store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      action.ID,
			ResponseName:  responseName,
			ActionType:    "shell",
			ConnectorName: connector.Name,
			TriggerPhase:  triggerPhase,
			Status:        "skipped",
			ErrorMessage:  "shell connector is disabled",
			ExecutedAt:    time.Now(),
		}
		return execLog, nil
	}

	// Build arguments: connector default_args + action shell_extra_args
	// Both support {var} expansion
	var args []string

	if connector.DefaultArgs != "" {
		expanded := expandParams(connector.DefaultArgs, attack, eventType, prefixStr, fa)
		args = append(args, splitArgs(expanded)...)
	}

	if action.ShellExtraArgs != "" {
		expanded := expandParams(action.ShellExtraArgs, attack, eventType, prefixStr, fa)
		args = append(args, splitArgs(expanded)...)
	}

	// Set up command with timeout
	timeout := 30 * time.Second
	if connector.TimeoutMs > 0 {
		timeout = time.Duration(connector.TimeoutMs) * time.Millisecond
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, connector.Command, args...)

	// If pass_stdin, pipe JSON payload via stdin
	if connector.PassStdin {
		payload := map[string]any{
			"event":        eventType,
			"attack_id":    attack.ID,
			"dst_ip":       attack.DstIP,
			"prefix":       prefixStr,
			"attack_type":  attack.AttackType,
			"severity":     attack.Severity,
			"peak_pps":     attack.PeakPPS,
			"peak_bps":     attack.PeakBPS,
			"reason_codes": attack.ReasonCodes,
			"node_sources": attack.NodeSources,
			"started_at":   attack.StartedAt.Format(time.RFC3339),
		}
		if attack.EndedAt != nil {
			payload["ended_at"] = attack.EndedAt.Format(time.RFC3339)
		}
		stdinData, _ := json.Marshal(payload)
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	// Capture stdout + stderr
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	execLog := &store.ActionExecutionLog{
		AttackID:      attackDBID,
		ActionID:      action.ID,
		ResponseName:  responseName,
		ActionType:    "shell",
		ConnectorName: connector.Name,
		TriggerPhase:  triggerPhase,
		RequestBody:   fmt.Sprintf("%s %s", connector.Command, strings.Join(args, " ")),
		ExecutedAt:    time.Now(),
	}

	start := time.Now()
	err = cmd.Run()
	execLog.DurationMs = int(time.Since(start).Milliseconds())

	// Truncate output to 1KB
	output := truncateStr(outBuf.String(), 1024)
	execLog.ResponseBody = output

	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			execLog.Status = "timeout"
			execLog.ErrorMessage = fmt.Sprintf("command timed out after %dms", connector.TimeoutMs)
		} else {
			execLog.Status = "failed"
			execLog.ErrorMessage = err.Error()
		}
		return execLog, err
	}

	exitCode := cmd.ProcessState.ExitCode()
	execLog.StatusCode = &exitCode
	if exitCode != 0 {
		execLog.Status = "failed"
		execLog.ErrorMessage = fmt.Sprintf("exit code %d", exitCode)
		return execLog, fmt.Errorf("shell command exited with code %d: %s", exitCode, output)
	}

	execLog.Status = "success"
	return execLog, nil
}

// splitArgs splits a space-separated argument string into individual args.
// Respects simple quoting (double quotes).
func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var args []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
