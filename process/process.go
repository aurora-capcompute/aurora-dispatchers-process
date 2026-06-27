package process

import (
	"github.com/aurora-capcompute/aurora-dispatchers/builtin"
	"github.com/aurora-capcompute/aurora-dispatchers/registry"
	"bytes"
	"github.com/aurora-capcompute/capcompute/dispatcher"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Exec = "process.exec"

type Rule struct {
	Executable string   `json:"executable"`
	ArgsPrefix []string `json:"args_prefix,omitempty"`
}

type Profile struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type Settings struct {
	Root                      string    `json:"root"`
	Profiles                  []Profile `json:"profiles,omitempty"`
	DenyExecutables           []string  `json:"deny_executables,omitempty"`
	EnvAllow                  []string  `json:"env_allow,omitempty"`
	ForwardHostEnv            []string  `json:"forward_host_env,omitempty"`
	MaxTimeoutMS              int64     `json:"max_timeout_ms,omitempty"`
	MaxOutputBytes            int64     `json:"max_output_bytes,omitempty"`
	MaxStdinBytes             int64     `json:"max_stdin_bytes,omitempty"`
	RequireApproval           *bool     `json:"require_approval,omitempty"`
	ApproveUnmatched          *bool     `json:"approve_unmatched,omitempty"`
	AllowWorkspaceExecutables bool      `json:"allow_workspace_executables,omitempty"`
}

type Request struct {
	Argv      []string          `json:"argv"`
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	TimeoutMS int64             `json:"timeout_ms,omitempty"`
	Stdin     string            `json:"stdin,omitempty"`
}

type Response struct {
	Argv       []string `json:"argv"`
	Cwd        string   `json:"cwd"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	DurationMS int64    `json:"duration_ms"`
	Truncated  bool     `json:"truncated,omitempty"`
	Approved   bool     `json:"approved,omitempty"`
}

type Registration struct{}

func (Registration) Matches(name string) bool { return name == Exec }

func (Registration) Normalize(name string, raw json.RawMessage) (json.RawMessage, error) {
	if name != Exec {
		return nil, fmt.Errorf("unsupported process capability %q", name)
	}
	var settings Settings
	if err := decodeStrict(raw, &settings); err != nil {
		return nil, err
	}
	if len(settings.Profiles) == 0 {
		settings.Profiles = defaultProfiles()
	}
	if len(settings.DenyExecutables) == 0 {
		settings.DenyExecutables = []string{"bash", "chmod", "chown", "curl", "doas", "docker", "fdisk", "kill", "mkfs", "mount", "nc", "podman", "reboot", "rm", "sh", "shutdown", "ssh", "sudo", "su", "umount", "wget", "zsh"}
	}
	if len(settings.EnvAllow) == 0 {
		settings.EnvAllow = []string{"CI", "GOCACHE", "GOFLAGS", "GOMODCACHE", "NODE_ENV", "NO_COLOR", "PYTHONPATH", "RUSTFLAGS", "TERM"}
	}
	if len(settings.ForwardHostEnv) == 0 {
		settings.ForwardHostEnv = []string{"HOME", "LANG", "PATH", "TMPDIR"}
	}
	if settings.MaxTimeoutMS == 0 {
		settings.MaxTimeoutMS = int64((10 * time.Minute) / time.Millisecond)
	}
	if settings.MaxOutputBytes == 0 {
		settings.MaxOutputBytes = 4 << 20
	}
	if settings.MaxStdinBytes == 0 {
		settings.MaxStdinBytes = 1 << 20
	}
	if settings.RequireApproval == nil {
		settings.RequireApproval = boolPtr(true)
	}
	if settings.ApproveUnmatched == nil {
		settings.ApproveUnmatched = boolPtr(true)
	}
	root, err := canonicalRoot(settings.Root)
	if err != nil {
		return nil, err
	}
	settings.Root = root
	if settings.MaxTimeoutMS <= 0 || settings.MaxOutputBytes <= 0 || settings.MaxStdinBytes < 0 {
		return nil, errors.New("process limits are invalid")
	}
	settings.DenyExecutables = cleanList(settings.DenyExecutables)
	settings.EnvAllow = cleanList(settings.EnvAllow)
	settings.ForwardHostEnv = cleanList(settings.ForwardHostEnv)
	seenProfiles := map[string]struct{}{}
	for i := range settings.Profiles {
		settings.Profiles[i].Name = strings.TrimSpace(settings.Profiles[i].Name)
		if settings.Profiles[i].Name == "" {
			return nil, errors.New("profile name is required")
		}
		if _, exists := seenProfiles[settings.Profiles[i].Name]; exists {
			return nil, fmt.Errorf("duplicate profile %q", settings.Profiles[i].Name)
		}
		seenProfiles[settings.Profiles[i].Name] = struct{}{}
		for j := range settings.Profiles[i].Rules {
			rule := &settings.Profiles[i].Rules[j]
			rule.Executable = strings.TrimSpace(rule.Executable)
			if rule.Executable == "" || strings.ContainsAny(rule.Executable, `/\`) {
				return nil, fmt.Errorf("profile %q has invalid executable %q", settings.Profiles[i].Name, rule.Executable)
			}
		}
		slices.SortFunc(settings.Profiles[i].Rules, func(a, b Rule) int {
			return strings.Compare(a.Executable+"\x00"+strings.Join(a.ArgsPrefix, "\x00"), b.Executable+"\x00"+strings.Join(b.ArgsPrefix, "\x00"))
		})
	}
	slices.SortFunc(settings.Profiles, func(a, b Profile) int { return strings.Compare(a.Name, b.Name) })
	return json.Marshal(settings)
}

func (Registration) IsSubset(_ string, parent, child json.RawMessage) error {
	var p, c Settings
	if err := json.Unmarshal(parent, &p); err != nil {
		return fmt.Errorf("decode parent settings: %w", err)
	}
	if err := json.Unmarshal(child, &c); err != nil {
		return fmt.Errorf("decode child settings: %w", err)
	}
	if p.Root != c.Root {
		return errors.New("child process root must equal parent root")
	}
	parentRules := flattenRules(p.Profiles)
	for _, rule := range flattenRules(c.Profiles) {
		if !slices.Contains(parentRules, rule) {
			return fmt.Errorf("child command rule %q is not allowed by parent", rule)
		}
	}
	for _, key := range c.EnvAllow {
		if !slices.Contains(p.EnvAllow, key) {
			return fmt.Errorf("child environment key %q is not allowed by parent", key)
		}
	}
	for _, key := range c.ForwardHostEnv {
		if !slices.Contains(p.ForwardHostEnv, key) {
			return fmt.Errorf("child host environment key %q is not allowed by parent", key)
		}
	}
	for _, executable := range p.DenyExecutables {
		if !slices.Contains(c.DenyExecutables, executable) {
			return fmt.Errorf("child removed denied executable %q", executable)
		}
	}
	if boolVal(p.RequireApproval) && !boolVal(c.RequireApproval) || !boolVal(p.ApproveUnmatched) && boolVal(c.ApproveUnmatched) ||
		!p.AllowWorkspaceExecutables && c.AllowWorkspaceExecutables {
		return errors.New("child process policy widens parent permissions")
	}
	if c.MaxTimeoutMS > p.MaxTimeoutMS || c.MaxOutputBytes > p.MaxOutputBytes || c.MaxStdinBytes > p.MaxStdinBytes {
		return errors.New("child process limits exceed parent limits")
	}
	return nil
}

func (Registration) Configure(_ context.Context, name string, raw json.RawMessage, _ registry.Services, config *builtin.Config) error {
	normalized, err := (Registration{}).Normalize(name, raw)
	if err != nil {
		return err
	}
	var settings Settings
	if err := json.Unmarshal(normalized, &settings); err != nil {
		return err
	}
	config.Handlers = append(config.Handlers, &Handler{settings: settings})
	config.Capabilities = append(config.Capabilities, dispatcher.Capability{
		Name:        Exec,
		Description: "Execute one bounded local process in " + settings.Root + ". Commands matching configured profiles run directly; unmatched commands require approval when enabled.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"},"minItems":1},"cwd":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"timeout_ms":{"type":"integer","minimum":1},"stdin":{"type":"string"}},"required":["argv"],"additionalProperties":false}`),
	})
	return nil
}

type Handler struct {
	settings Settings
}

func (*Handler) Handles(name string) bool { return name == Exec }

func (h *Handler) DispatchCall(ctx context.Context, call dispatcher.Call, auth dispatcher.Authorization) (dispatcher.Outcome, error) {
	var req Request
	if err := decodeStrict(call.Args, &req); err != nil {
		return dispatcher.Fail("decode process.exec request: " + err.Error()), nil
	}
	decision, err := h.classify(req)
	if err != nil {
		return dispatcher.Fail(err.Error()), nil
	}
	approved := false
	if boolVal(h.settings.RequireApproval) || decision == commandApproval {
		if auth.Decision != dispatcher.Approved {
			return dispatcher.Yield("Approve local command: " + quoteArgv(req.Argv)), nil
		}
		approved = true
	}
	response, err := h.execute(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return dispatcher.Outcome{}, ctx.Err()
		}
		return dispatcher.Fail(err.Error()), nil
	}
	response.Approved = approved
	raw, err := json.Marshal(response)
	if err != nil {
		return dispatcher.Outcome{}, err
	}
	return dispatcher.Result(raw), nil
}

type commandDecision int

const (
	commandAllowed commandDecision = iota
	commandApproval
)

func (h *Handler) classify(req Request) (commandDecision, error) {
	if len(req.Argv) == 0 || strings.TrimSpace(req.Argv[0]) == "" {
		return 0, errors.New("argv must contain an executable")
	}
	executable := req.Argv[0]
	base := filepath.Base(executable)
	if isAlwaysDenied(base, req.Argv[1:]) || slices.Contains(h.settings.DenyExecutables, base) {
		return 0, fmt.Errorf("executable %q is denied", base)
	}
	if strings.ContainsAny(executable, `/\`) {
		if !h.settings.AllowWorkspaceExecutables {
			return 0, errors.New("executable paths are disabled")
		}
		if err := h.validateWorkspaceExecutable(executable); err != nil {
			return 0, err
		}
		base = filepath.Base(executable)
	}
	for _, profile := range h.settings.Profiles {
		for _, rule := range profile.Rules {
			if base == rule.Executable && hasPrefix(req.Argv[1:], rule.ArgsPrefix) {
				return commandAllowed, nil
			}
		}
	}
	if boolVal(h.settings.ApproveUnmatched) {
		return commandApproval, nil
	}
	return 0, fmt.Errorf("command %q does not match an allowed profile", base)
}

func (h *Handler) execute(ctx context.Context, req Request) (Response, error) {
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if req.TimeoutMS == 0 {
		timeout = time.Duration(h.settings.MaxTimeoutMS) * time.Millisecond
	}
	if timeout <= 0 || timeout > time.Duration(h.settings.MaxTimeoutMS)*time.Millisecond {
		return Response{}, errors.New("timeout exceeds configured maximum")
	}
	if int64(len(req.Stdin)) > h.settings.MaxStdinBytes {
		return Response{}, errors.New("stdin exceeds configured maximum")
	}
	cwd, rel, err := h.resolveCwd(req.Cwd)
	if err != nil {
		return Response{}, err
	}
	for key := range req.Env {
		if !slices.Contains(h.settings.EnvAllow, key) {
			return Response{}, fmt.Errorf("environment key %q is not allowed", key)
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.Command(req.Argv[0], req.Argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = h.environment(req.Env)
	cmd.Stdin = strings.NewReader(req.Stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout := &limitBuffer{limit: h.settings.MaxOutputBytes}
	stderr := &limitBuffer{limit: h.settings.MaxOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return Response{}, err
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-runCtx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-wait
		return Response{}, runCtx.Err()
	}
	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return Response{}, waitErr
		}
		exitCode = exitErr.ExitCode()
	}
	return Response{
		Argv: append([]string(nil), req.Argv...), Cwd: rel, ExitCode: exitCode,
		Stdout: stdout.String(), Stderr: stderr.String(),
		DurationMS: time.Since(start).Milliseconds(), Truncated: stdout.truncated || stderr.truncated,
	}, nil
}

func (h *Handler) resolveCwd(input string) (string, string, error) {
	if input == "" {
		return h.settings.Root, ".", nil
	}
	if filepath.IsAbs(input) {
		return "", "", errors.New("absolute cwd is not allowed")
	}
	clean := filepath.Clean(input)
	full := filepath.Join(h.settings.Root, clean)
	rel, err := filepath.Rel(h.settings.Root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("cwd escapes process root")
	}
	info, err := os.Stat(full)
	if err != nil {
		return "", "", err
	}
	if !info.IsDir() {
		return "", "", errors.New("cwd is not a directory")
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", "", err
	}
	if !insideRoot(h.settings.Root, resolved) {
		return "", "", errors.New("cwd symlink escapes process root")
	}
	return resolved, filepath.ToSlash(rel), nil
}

func (h *Handler) validateWorkspaceExecutable(input string) error {
	if filepath.IsAbs(input) {
		return errors.New("absolute executable paths are disabled")
	}
	full := filepath.Join(h.settings.Root, filepath.Clean(input))
	if !insideRoot(h.settings.Root, full) {
		return errors.New("executable escapes process root")
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return err
	}
	if !insideRoot(h.settings.Root, resolved) {
		return errors.New("executable symlink escapes process root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return errors.New("workspace executable is not an executable regular file")
	}
	return nil
}

func (h *Handler) environment(overrides map[string]string) []string {
	result := make([]string, 0, len(h.settings.ForwardHostEnv)+len(overrides))
	for _, key := range h.settings.ForwardHostEnv {
		if value, ok := os.LookupEnv(key); ok {
			result = append(result, key+"="+value)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	slices.Sort(result)
	return result
}

type limitBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *limitBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(data)
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(data)
	return original, nil
}

func (b *limitBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func canonicalRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("root is not a directory")
	}
	return filepath.Clean(abs), nil
}

func decodeStrict(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func cleanList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return result
}

func flattenRules(profiles []Profile) []string {
	var result []string
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			result = append(result, rule.Executable+"\x00"+strings.Join(rule.ArgsPrefix, "\x00"))
		}
	}
	slices.Sort(result)
	return result
}

func hasPrefix(values, prefix []string) bool {
	return len(values) >= len(prefix) && slices.Equal(values[:len(prefix)], prefix)
}

func isAlwaysDenied(executable string, args []string) bool {
	switch executable {
	case "env":
		return true
	case "git":
		for _, arg := range args {
			if arg == "push" || arg == "fetch" || arg == "pull" || arg == "remote" {
				return true
			}
		}
	case "npm", "pnpm", "yarn":
		for _, arg := range args {
			if arg == "publish" {
				return true
			}
		}
	}
	return false
}

func quoteArgv(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		if strings.ContainsAny(arg, " \t\n\"'") {
			raw, _ := json.Marshal(arg)
			quoted[i] = string(raw)
		} else {
			quoted[i] = arg
		}
	}
	return strings.Join(quoted, " ")
}

func insideRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func boolPtr(v bool) *bool { return &v }

func boolVal(p *bool) bool { return p != nil && *p }

func defaultProfiles() []Profile {
	return []Profile{
		{Name: "go", Rules: []Rule{
			{Executable: "go", ArgsPrefix: []string{"build"}},
			{Executable: "go", ArgsPrefix: []string{"test"}},
			{Executable: "go", ArgsPrefix: []string{"vet"}},
			{Executable: "go", ArgsPrefix: []string{"fmt"}},
			{Executable: "go", ArgsPrefix: []string{"mod"}},
			{Executable: "gofmt"},
		}},
		{Name: "python", Rules: []Rule{
			{Executable: "python", ArgsPrefix: []string{"-m", "pytest"}},
			{Executable: "python3", ArgsPrefix: []string{"-m", "pytest"}},
			{Executable: "pytest"},
		}},
		{Name: "rust", Rules: []Rule{
			{Executable: "cargo", ArgsPrefix: []string{"build"}},
			{Executable: "cargo", ArgsPrefix: []string{"test"}},
			{Executable: "cargo", ArgsPrefix: []string{"check"}},
			{Executable: "cargo", ArgsPrefix: []string{"clippy"}},
			{Executable: "cargo", ArgsPrefix: []string{"fmt"}},
			{Executable: "rustfmt"},
		}},
		{Name: "node", Rules: []Rule{
			{Executable: "npm", ArgsPrefix: []string{"test"}},
			{Executable: "npm", ArgsPrefix: []string{"run"}},
		}},
		{Name: "build", Rules: []Rule{{Executable: "make"}}},
	}
}
