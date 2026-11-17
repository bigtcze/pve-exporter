# Code quality for Go

Prefer idiomatic, readable Go and focused changes that respect existing package boundaries. Avoid duplicate parsers, excessive abstraction and unused layers. Check every relevant error and close response bodies; use descriptive failures without exposing credentials.

Network and local I/O must be bounded by context/deadlines, size limits and safe cleanup. Handle concurrency and shared ticket/cached state without races, deadlocks, unbounded goroutines or nondeterministic emitted metrics. Preserve Prometheus descriptor consistency and stable public output.

Keep module dependencies justified and reproducible. Use the Go version declared in `go.mod`, with mise as the local/CI tool runner; use pinned golangci-lint. Never make a check pass by disabling useful linters, tests or security validations. Document actual compatibility and operational impacts of nontrivial changes.
