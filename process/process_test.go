package process

import (
	"aurora-dispatchers/resolution"
	"capcompute/dispatcher"
	"context"
	"encoding/json"
	"testing"
)

func handler(t *testing.T, extra string) *Handler {
	t.Helper()
	root := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"root": root})
	if extra != "" {
		raw = json.RawMessage(`{"root":` + quote(root) + `,` + extra + `}`)
	}
	normalized, err := (Registration{}).Normalize(Exec, raw)
	if err != nil {
		t.Fatal(err)
	}
	var settings Settings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		t.Fatal(err)
	}
	return &Handler{settings: settings}
}

func TestProfileCommandRuns(t *testing.T) {
	h := handler(t, `"require_approval":false,"profiles":[{"name":"test","rules":[{"executable":"printf"}]}]`)
	out, err := h.DispatchCall(context.Background(), dispatcher.Call{
		Name: Exec, Args: json.RawMessage(`{"argv":["printf","hello"]}`),
	})
	if err != nil || out.Kind() != dispatcher.OutcomeResult {
		t.Fatalf("outcome=%v message=%q err=%v", out.Kind(), out.Message(), err)
	}
	var response Response
	_ = json.Unmarshal(out.Result(), &response)
	if response.Stdout != "hello" || response.ExitCode != 0 {
		t.Fatalf("response=%#v", response)
	}
}

func TestUnmatchedYieldsThenRunsAfterApproval(t *testing.T) {
	h := handler(t, `"profiles":[]`)
	call := dispatcher.Call{Name: Exec, Args: json.RawMessage(`{"argv":["printf","ok"]}`)}
	out, _ := h.DispatchCall(context.Background(), call)
	if out.Kind() != dispatcher.OutcomeYield {
		t.Fatalf("expected yield, got %v", out.Kind())
	}
	ctx := resolution.WithContext(context.Background(), resolution.Resolution{Decision: resolution.Approved})
	out, _ = h.DispatchCall(ctx, call)
	if out.Kind() != dispatcher.OutcomeResult {
		t.Fatalf("expected result, got %v: %s", out.Kind(), out.Message())
	}
}

func TestDeniedExecutableCannotBeApproved(t *testing.T) {
	h := handler(t, "")
	ctx := resolution.WithContext(context.Background(), resolution.Resolution{Decision: resolution.Approved})
	out, _ := h.DispatchCall(ctx, dispatcher.Call{Name: Exec, Args: json.RawMessage(`{"argv":["sh","-c","echo bad"]}`)})
	if out.Kind() != dispatcher.OutcomeFailed {
		t.Fatalf("expected failure, got %v", out.Kind())
	}
}

func TestEnvironmentIsExplicit(t *testing.T) {
	h := handler(t, `"require_approval":false,"profiles":[{"name":"test","rules":[{"executable":"printenv"}]}],"env_allow":["SAFE"],"forward_host_env":[]`)
	out, _ := h.DispatchCall(context.Background(), dispatcher.Call{
		Name: Exec, Args: json.RawMessage(`{"argv":["printenv","SAFE"],"env":{"SAFE":"yes"}}`),
	})
	if out.Kind() != dispatcher.OutcomeResult {
		t.Fatalf("outcome=%v: %s", out.Kind(), out.Message())
	}
	var response Response
	_ = json.Unmarshal(out.Result(), &response)
	if response.Stdout != "yes\n" {
		t.Fatalf("stdout=%q", response.Stdout)
	}
}

func quote(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
