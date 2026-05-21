# Security Policy

## Supported Versions

Security fixes are released for the latest minor version. Before a `1.0.0` release, only the latest published `0.x` version is supported.

## Reporting a Vulnerability

Please report security issues privately by opening a GitHub security advisory or emailing the maintainers listed in the repository metadata.

Include:

- affected version or commit
- reproduction steps
- expected and actual behavior
- whether sensitive data was exposed

Please do not open public issues for vulnerabilities that include exploit details or sensitive samples.

## Privacy and Data Handling

PromptGuard is local-only by default:

- no API keys are required
- no environment variables are required
- no network calls are made
- no telemetry is collected

Scanner results may include evidence snippets from the input text. If inputs can contain secrets or PII, use redaction or disable evidence in downstream logs.

GitHub secret scanning should be enabled on the public repository. This project also runs dependency audit and CodeQL in GitHub Actions.

## Out of Scope

The following are not security vulnerabilities by themselves:

- missed detections on arbitrary prompt-injection phrasing
- missed PII formats outside the documented pattern-based scope
- contradiction misses that require full natural language inference

Please report those as benchmark or detector-improvement issues instead.
