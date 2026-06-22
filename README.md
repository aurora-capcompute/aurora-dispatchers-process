# aurora-dispatchers-process

Policy-controlled synchronous local process execution for Aurora.

The dispatcher exposes `process.exec`. It accepts an executable and argument
array and never invokes a shell. Commands matching configured profiles run
directly, unmatched commands may yield for approval, and explicit deny rules
cannot be overridden by approval.

```go
registry.New(process.Registration{})
```

```json
{
  "name": "process.exec",
  "settings": {
    "root": "/home/user/project",
    "profiles": [{
      "name": "go",
      "rules": [
        {"executable": "go"},
        {"executable": "gofmt"}
      ]
    }],
    "env_allow": ["GOCACHE", "GOFLAGS"],
    "forward_host_env": ["HOME", "PATH", "TMPDIR"],
    "approve_unmatched": true
  }
}
```

This dispatcher runs on the host. It constrains command shape, cwd, environment,
duration, output, stdin, and cancellation, but it cannot enforce filesystem or
network isolation.
