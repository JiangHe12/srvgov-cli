package cmd

import (
	"testing"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
)

func requireMutationPair(
	t *testing.T,
	events []srvgovaudit.Event,
	action, contextName, riskTier string,
) (srvgovaudit.Event, srvgovaudit.Event) {
	t.Helper()
	matches := make([]srvgovaudit.Event, 0, 2)
	for _, event := range events {
		if event.Action == action && event.Context.Name == contextName {
			matches = append(matches, event)
		}
	}
	if len(matches) != 2 {
		t.Fatalf("mutation %s/%s events = %#v, want intent and outcome", action, contextName, matches)
	}
	var intent, outcome srvgovaudit.Event
	for _, event := range matches {
		switch event.Phase {
		case mutationAuditPhaseIntent:
			intent = event
		case mutationAuditPhaseOutcome:
			outcome = event
		default:
			t.Fatalf("mutation event has invalid phase: %#v", event)
		}
	}
	if intent.MutationID == "" || intent.MutationID != outcome.MutationID ||
		intent.Status != "pending" ||
		outcome.Outcome == nil ||
		intent.RiskTier != riskTier ||
		outcome.RiskTier != riskTier {
		t.Fatalf("invalid mutation pair: intent=%#v outcome=%#v", intent, outcome)
	}
	return intent, outcome
}
