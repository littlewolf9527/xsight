package api

import (
	"context"
	"fmt"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// GlobalPrefix is the virtual prefix used for global threshold detection.
const GlobalPrefix = "0.0.0.0/0"

// isGlobalPrefix returns true if the CIDR is the virtual global prefix.
func isGlobalPrefix(cidr string) bool {
	return cidr == GlobalPrefix
}

// responseHasXDropOrBGP checks if a response contains any xDrop or BGP action.
func responseHasXDropOrBGP(ctx context.Context, s store.Store, responseID int) (bool, error) {
	actions, err := s.Responses().ListActions(ctx, responseID)
	if err != nil {
		return false, err
	}
	for _, a := range actions {
		if a.ActionType == "xdrop" || a.ActionType == "bgp" {
			return true, nil
		}
	}
	return false, nil
}

// isResponseReferencedByGlobalPrefix checks if a response is used by any threshold rule
// or template default_response that is bound to the global prefix (0.0.0.0/0).
func isResponseReferencedByGlobalPrefix(ctx context.Context, s store.Store, responseID int) (bool, error) {
	// Get all prefix IDs and template IDs associated with 0.0.0.0/0
	prefixes, err := s.Prefixes().List(ctx)
	if err != nil {
		return false, err
	}
	globalPrefixIDs := make(map[int]bool)
	globalTemplateIDs := make(map[int]bool)
	for _, p := range prefixes {
		if isGlobalPrefix(p.Prefix) {
			globalPrefixIDs[p.ID] = true
			if p.ThresholdTemplateID != nil {
				globalTemplateIDs[*p.ThresholdTemplateID] = true
			}
		}
	}
	if len(globalPrefixIDs) == 0 {
		return false, nil // no global prefix configured
	}

	// Check threshold rules: rules with this response_id on a global-prefix template
	thresholds, err := s.Thresholds().List(ctx)
	if err != nil {
		return false, err
	}
	for _, th := range thresholds {
		if th.ResponseID == nil || *th.ResponseID != responseID {
			continue
		}
		if th.PrefixID != nil && globalPrefixIDs[*th.PrefixID] {
			return true, nil
		}
		if th.TemplateID != nil && globalTemplateIDs[*th.TemplateID] {
			return true, nil
		}
	}

	// Check template default_response_id
	templates, err := s.ThresholdTemplates().List(ctx)
	if err != nil {
		return false, err
	}
	for _, t := range templates {
		if t.ResponseID != nil && *t.ResponseID == responseID && globalTemplateIDs[t.ID] {
			return true, nil
		}
	}

	return false, nil
}

// prefixForThresholdRule returns the CIDR of the prefix associated with a threshold rule.
// Works for both direct prefix rules (prefix_id) and template rules (template_id → prefix binding).
func prefixForThresholdRule(ctx context.Context, s store.Store, th *store.Threshold) (string, error) {
	// Direct prefix rule
	if th.PrefixID != nil {
		prefixes, err := s.Prefixes().List(ctx)
		if err != nil {
			return "", err
		}
		for _, p := range prefixes {
			if p.ID == *th.PrefixID {
				return p.Prefix, nil
			}
		}
	}
	// Template rule — check if any global prefix uses this template
	if th.TemplateID != nil {
		prefixes, err := s.Prefixes().List(ctx)
		if err != nil {
			return "", err
		}
		for _, p := range prefixes {
			if p.ThresholdTemplateID != nil && *p.ThresholdTemplateID == *th.TemplateID && isGlobalPrefix(p.Prefix) {
				return p.Prefix, nil
			}
		}
	}
	return "", nil
}

// validateGlobalPrefixConstraints checks global prefix + outbound direction rules:
// 1. Global (0.0.0.0/0): domain=internal_ip not allowed
// 2. Global (0.0.0.0/0): response with xDrop/BGP not allowed
// 3. Outbound (sends): response with xDrop/BGP not allowed (would block internal hosts)
func validateGlobalPrefixConstraints(ctx context.Context, s store.Store, th *store.Threshold) error {
	// Check if this rule is under a global prefix
	pfx, err := prefixForThresholdRule(ctx, s, th)
	if err != nil {
		return fmt.Errorf("validation lookup failed: %w", err)
	}
	if isGlobalPrefix(pfx) {
		if th.Domain == "internal_ip" {
			return fmt.Errorf("global prefix (0.0.0.0/0) only supports subnet-level rules, not internal_ip")
		}
		if th.ResponseID != nil {
			hasXDrop, err := responseHasXDropOrBGP(ctx, s, *th.ResponseID)
			if err != nil {
				return fmt.Errorf("validation lookup failed: %w", err)
			}
			if hasXDrop {
				return fmt.Errorf("global prefix (0.0.0.0/0) rules cannot use responses containing xDrop/BGP actions")
			}
		}
	}

	// Outbound (sends) rules cannot use xDrop/BGP (would block internal source IPs)
	if th.Direction == "sends" && th.ResponseID != nil {
		hasXDrop, err := responseHasXDropOrBGP(ctx, s, *th.ResponseID)
		if err != nil {
			return fmt.Errorf("validation lookup failed: %w", err)
		}
		if hasXDrop {
			return fmt.Errorf("outbound (sends) rules cannot use responses containing xDrop/BGP actions")
		}
	}
	return nil
}
