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

//nolint:unparam // Keep the expected tier explicit for future protected-read tests.
func requireReadAuditPairs(
	t *testing.T,
	events []srvgovaudit.Event,
	action, riskTier string,
	want int,
) []srvgovaudit.Event {
	t.Helper()
	type pair struct {
		intent  *srvgovaudit.Event
		outcome *srvgovaudit.Event
	}
	pairs := make(map[string]*pair, want)
	outcomes := make([]srvgovaudit.Event, 0, want)
	for index := range events {
		event := events[index]
		if event.Action != action || event.OperationID == "" {
			continue
		}
		current := pairs[event.OperationID]
		if current == nil {
			current = &pair{}
			pairs[event.OperationID] = current
		}
		switch event.Phase {
		case readAuditPhaseIntent:
			current.intent = &event
		case readAuditPhaseOutcome:
			current.outcome = &event
			outcomes = append(outcomes, event)
		default:
			t.Fatalf("read event has invalid phase: %#v", event)
		}
	}
	if len(pairs) != want || len(outcomes) != want {
		t.Fatalf("read %s pairs = %#v, want %d", action, pairs, want)
	}
	for id, current := range pairs {
		if current.intent == nil || current.outcome == nil ||
			current.intent.OperationID != current.outcome.OperationID ||
			current.intent.Status != "pending" ||
			current.intent.EventType != srvgovaudit.EventType(action+"."+readAuditPhaseIntent) ||
			current.outcome.EventType != srvgovaudit.EventType(action) ||
			current.outcome.ReadOutcome == nil ||
			current.intent.RiskTier != riskTier ||
			current.outcome.RiskTier != riskTier {
			t.Fatalf("invalid read pair %s: intent=%#v outcome=%#v", id, current.intent, current.outcome)
		}
	}
	return outcomes
}
