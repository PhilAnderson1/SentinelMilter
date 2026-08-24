# SentinelMilter

[![CI](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml)

SentinelMilter is a Go Postfix milter that sends selected message headers and decoded text content to an OpenRouter-compatible `v1/chat/completions` endpoint. It validates the model's JSON decision and can either observe decisions or enforce rejection.

## Safety model

- `monitor` mode always accepts mail and logs the model's proposed action.
- `enforce` mode rejects `spam` or `scam` decisions at or above `reject_score`.
- AI errors fail open by default. Set `ai_error_action: tempfail` if desired in enforce mode.
- Message and prompt sizes, request duration, MIME depth, and concurrent AI calls are bounded.
- HTML link text and its actual destination are preserved together for deception analysis.
- API keys are never deliberately logged. Message bodies are never logged.

Start in monitor mode and review results before enabling enforcement.

## Build and install

Go 1.22 or later is required.

```sh
git clone https://github.com/PhilAnderson1/SentinelMilter.git
cd SentinelMilter
go test ./...
go build -trimpath -o sentinelmilter ./cmd/sentinelmilter
sudo install -m 0755 sentinelmilter /usr/local/sbin/sentinelmilter
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin sentinelmilter
sudo install -d -o root -g sentinelmilter -m 0750 /etc/sentinelmilter
sudo install -o root -g sentinelmilter -m 0640 configs/sentinelmilter.yaml /etc/sentinelmilter/
sudo install -o root -g sentinelmilter -m 0640 configs/detection-prompt.txt /etc/sentinelmilter/
sudo install -m 0644 packaging/systemd/sentinelmilter.service /etc/systemd/system/
```

Put the OpenRouter key in `ai.api_key`, or configure `ai.api_key_env` and provide that variable to the service. Validate before starting:

For Qwen models served by llama.cpp, set `ai.disable_thinking: true` to request non-thinking mode per message. SentinelMilter sends `thinking_budget_tokens: 0`. Leave it `false` for normal reasoning. Recent llama.cpp builds can also disable reasoning globally by starting `llama-server` with `--reasoning off`.

```sh
/usr/local/sbin/sentinelmilter --config /etc/sentinelmilter/sentinelmilter.yaml --check-config
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelmilter
```

## Postfix

Add to `main.cf` (adjust timeouts to remain above the AI timeout):

```text
smtpd_milters = unix:/run/sentinelmilter/sentinelmilter.sock
non_smtpd_milters = unix:/run/sentinelmilter/sentinelmilter.sock
milter_default_action = accept
milter_protocol = 6
```

The Postfix process must be able to access the socket directory. On installations where Postfix SMTP runs chrooted, expose the socket inside its chroot or use a loopback TCP listener with appropriate firewalling.

Logs are JSON records in the systemd journal. A successful decision records both `proposed_action` and `actual_action`, making monitor-mode evaluation explicit.

## License

SentinelMilter is available under the [MIT License](LICENSE).
