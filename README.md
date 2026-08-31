# SentinelMilter

[![CI](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml)

SentinelMilter is an AI-powered mail filter for identifying and rejecting unwanted email. It has been tested with Postfix but is designed to work with any MTA that supports the Sendmail Milter protocol.

## Why SentinelMilter?

- Scans inbound and outbound email, helping protect your server's sending reputation.
- Uses semantic analysis to detect unwanted email by meaning, not just keywords or signatures.
- Performs forensic AI analysis of message headers, body content, and hyperlink destinations.
- Installs easily as a single, statically linked binary with no runtime dependencies.
- Cost-effective to operate at approximately $0.35 per 1,000 emails with the suggested LLM, depending on message length and provider pricing.
- Provides a safe monitor mode that logs classifications and proposed actions without blocking email.
- Avoids provider lock-in by supporting compatible hosted AI services and locally operated AI models.

SentinelMilter works with OpenRouter and llama.cpp-style `v1/chat/completions` endpoints, supporting both hosted AI models and local inference.

## Install

Download the archive for your system from the [latest SentinelMilter release](https://github.com/PhilAnderson1/SentinelMilter/releases/latest):

| Linux architecture | Release archive suffix |
| --- | --- |
| x86-64 / AMD64 | `linux-amd64.tar.gz` |
| ARM64 / AArch64 | `linux-arm64.tar.gz` |
| 32-bit x86 | `linux-386.tar.gz` |
| ARMv7 | `linux-armv7.tar.gz` |

Extract the downloaded archive and run its installer. For example, for an AMD64 system:

```sh
tar -xzf sentinelmilter-v0.1.0-linux-amd64.tar.gz
cd sentinelmilter-v0.1.0
sudo ./install.sh
```

The release binaries are statically linked. The installer places the executable in `/usr/local/sbin`, installs the configuration files in `/etc/sentinelmilter`, and installs the systemd unit when systemd is available. Existing configuration files are preserved.

Edit `/etc/sentinelmilter/sentinelmilter.yaml` and set the endpoint, model, and API key. Alternatively, configure `ai.api_key_env` and make that environment variable available to the service. For compatible reasoning models served through OpenRouter or llama.cpp, set `ai.disable_thinking: true` to request non-thinking mode for faster classification.

Validate the configuration before enabling the service:

```sh
sudo /usr/local/sbin/sentinelmilter --config /etc/sentinelmilter/sentinelmilter.yaml --check-config
sudo systemctl enable --now sentinelmilter
```

## Build from source

If a prebuilt binary is not suitable for your system, build SentinelMilter with Go 1.22 or later:

```sh
git clone https://github.com/PhilAnderson1/SentinelMilter.git
cd SentinelMilter
go test ./...
CGO_ENABLED=0 go build -trimpath -o sentinelmilter ./cmd/sentinelmilter
```

Install the resulting binary, configuration, prompt, and systemd unit:

```sh
sudo install -m 0755 sentinelmilter /usr/local/sbin/sentinelmilter
getent group sentinelmilter >/dev/null || sudo groupadd --system sentinelmilter
id sentinelmilter >/dev/null 2>&1 || sudo useradd --system --gid sentinelmilter --home-dir /nonexistent --shell /usr/sbin/nologin sentinelmilter
sudo install -d -o root -g sentinelmilter -m 0750 /etc/sentinelmilter
sudo install -o root -g sentinelmilter -m 0640 configs/sentinelmilter.yaml /etc/sentinelmilter/
sudo install -o root -g sentinelmilter -m 0640 configs/detection-prompt.txt /etc/sentinelmilter/
sudo install -m 0644 packaging/systemd/sentinelmilter.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Then edit and validate the configuration as described in the installation section above.

## Postfix

Add to `main.cf` (ensure Postfix's milter content timeout remains above the AI timeout):

```text
smtpd_milters = inet:127.0.0.1:8895
non_smtpd_milters = inet:127.0.0.1:8895
milter_default_action = accept
milter_protocol = 6
```

SentinelMilter also supports Unix sockets, for example `unix:/run/sentinelmilter/sentinelmilter.sock`. The Postfix process must be able to access the socket and its parent directory; on installations where Postfix SMTP runs chrooted, expose the socket inside its chroot. Keep TCP listeners bound to a loopback address unless access is restricted separately.

Logs are JSON records in the systemd journal. A successful decision records both `proposed_action` and `actual_action`, making monitor-mode evaluation explicit.

## License

SentinelMilter is available under the [MIT License](LICENSE).
