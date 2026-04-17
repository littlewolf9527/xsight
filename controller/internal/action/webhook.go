package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// webhookConfig is the parsed action config for webhook type.
type webhookConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"` // default POST
	Headers map[string]string `json:"headers"`
}

// executeWebhook executes a webhook action from response_actions config.
func executeWebhook(ctx context.Context, configJSON []byte, attack *store.Attack, eventType string) (string, error) {
	var cfg webhookConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return "", fmt.Errorf("parse webhook config: %w", err)
	}
	if cfg.URL == "" {
		return "", fmt.Errorf("webhook config missing url")
	}
	if cfg.Method == "" {
		cfg.Method = "POST"
	}

	return postWebhookWithConfig(ctx, cfg.URL, cfg.Method, cfg.Headers, attack, eventType, nil)
}

// postWebhook sends a notification to a global webhook endpoint.
func postWebhook(ctx context.Context, url string, headersJSON json.RawMessage, attack *store.Attack, eventType string) (string, error) {
	return postWebhookWithFA(ctx, url, headersJSON, attack, eventType, nil)
}

// postWebhookWithFA sends a webhook with optional FlowAnalysis data.
func postWebhookWithFA(ctx context.Context, url string, headersJSON json.RawMessage, attack *store.Attack, eventType string, fa *FlowAnalysis) (string, error) {
	var headers map[string]string
	if len(headersJSON) > 0 {
		if err := json.Unmarshal(headersJSON, &headers); err != nil {
			log.Printf("webhook: malformed headers JSON for %s: %v — sending without custom headers", url, err)
		}
	}
	return postWebhookWithConfig(ctx, url, "POST", headers, attack, eventType, fa)
}

func postWebhookWithConfig(ctx context.Context, url, method string, headers map[string]string, attack *store.Attack, eventType string, fa *FlowAnalysis) (string, error) {
	// Build payload
	payload := map[string]any{
		"event":        eventType,
		"attack_id":    attack.ID,
		"dst_ip":       attack.DstIP,
		"decoder":      attack.DecoderFamily,
		"attack_type":  attack.AttackType,
		"severity":     attack.Severity,
		"confidence":   attack.Confidence,
		"peak_pps":     attack.PeakPPS,
		"peak_bps":     attack.PeakBPS,
		"reason_codes": attack.ReasonCodes,
		"node_sources": attack.NodeSources,
		"started_at":   attack.StartedAt.Format(time.RFC3339),
		"timestamp":    time.Now().Format(time.RFC3339),
	}
	if attack.EndedAt != nil {
		payload["ended_at"] = attack.EndedAt.Format(time.RFC3339)
		payload["duration_seconds"] = int(attack.EndedAt.Sub(attack.StartedAt).Seconds())
	}
	// Include end_reason for attack_end events
	if eventType == "attack_end" {
		endReason := "expired"
		for _, rc := range attack.ReasonCodes {
			if rc == "evicted_by_cap" {
				endReason = "evicted_by_cap"
				break
			}
		}
		payload["end_reason"] = endReason
	}
	// Flow analysis fields (Phase 4)
	if fa != nil {
		payload["top_src_ips"] = fa.TopSrcIPs
		payload["top_src_ports"] = fa.TopSrcPorts
		payload["top_dst_ports"] = fa.TopDstPorts
		payload["dominant_src_port"] = fa.DominantSrcPort
		payload["dominant_src_port_pct"] = fa.DominantSrcPortPct
		payload["unique_src_ips"] = fa.UniqueSrcIPs
		if fa.FlowSummaryJSON != "" {
			payload["flow_summary_json"] = json.RawMessage(fa.FlowSummaryJSON)
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xsight-controller/1.0")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP %s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	result := fmt.Sprintf("HTTP %d", resp.StatusCode)

	if resp.StatusCode >= 400 {
		return result, fmt.Errorf("%s: %s", result, string(respBody))
	}
	return result, nil
}
