# SentinelMilter

[![CI](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml)

SentinelMilter is an AI-powered mail filter for identifying and rejecting unwanted email. It has been tested with Postfix but is designed to work with any MTA that supports the Sendmail Milter protocol.

## Why SentinelMilter?

- Uses semantic analysis to detect unwanted email by meaning, not just keywords or signatures.
- Performs forensic AI analysis of message headers, body content, and hyperlink destinations.
- Reads text embedded in images to detect scams that evade conventional text-based filters.
- Smart correspondent allowlisting learns trusted relationships and recurring legitimate senders, reducing false positives and unnecessary AI scans.
- Automatically builds persistent IP reputation to block repeat offenders without repeated AI analysis.
- Can scan inbound and outbound email, helping protect your server's sending reputation.
- Installs easily as a single, statically linked binary with no runtime dependencies.
- Provides a safe monitor mode that logs classifications and proposed actions without blocking email.
- Cost-effective to operate at approximately $0.35 per 1,000 scanned emails with the suggested LLM, depending on message length and provider pricing.
- Avoids provider lock-in by supporting compatible hosted AI services and locally hosted AI models.

SentinelMilter works with OpenRouter and llama.cpp-style `v1/chat/completions` AI endpoints.

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

### Configuration

Edit `/etc/sentinelmilter/sentinelmilter.yaml` before starting the service. To use a hosted model, create an account and API key at [OpenRouter](https://openrouter.ai/), then add the key and desired model to the `ai` section. Alternatively, change the endpoint and model to use a locally operated llama.cpp `v1/chat/completions` server. An API key can be stored in `ai.api_key` or supplied through the environment variable named by `ai.api_key_env`.

Leave SentinelMilter in `monitor` mode initially so that it records classifications and proposed actions without rejecting messages.

For Postfix, add the following to `main.cf` (ensure Postfix's milter content timeout remains above the AI timeout):

```text
smtpd_milters = inet:127.0.0.1:8895
non_smtpd_milters = inet:127.0.0.1:8895
milter_default_action = accept
milter_protocol = 6
```

SentinelMilter uses DKIM, SPF and DMARC results supplied by earlier mail filters as evidence. List authentication Milters before SentinelMilter in your Postfix configuration to improve classification accuracy.

Keep TCP listeners bound to a loopback address unless access is restricted separately.

Validate the configuration before enabling the service:

```sh
sudo /usr/local/sbin/sentinelmilter --config /etc/sentinelmilter/sentinelmilter.yaml --check-config
sudo systemctl enable --now sentinelmilter
```

Reload Postfix after changing `main.cf`:

```sh
sudo postfix reload
```

Send representative legitimate and unwanted test messages, then monitor SentinelMilter's classifications, scores, reasons, proposed actions, and actual actions:

```sh
sudo journalctl -u sentinelmilter --since yesterday --no-pager -o cat
```

Once monitor-mode results are satisfactory, change `mode: monitor` to `mode: enforce` in `/etc/sentinelmilter/sentinelmilter.yaml` and restart SentinelMilter:

```sh
sudo systemctl restart sentinelmilter
```

To add or remove correspondent whitelist entries manually, stop SentinelMilter while editing its database:

```sh
sudo systemctl stop sentinelmilter
sudo sentinelmilter --whitelist-add sender@example.com recipient@example.net
sudo sentinelmilter --whitelist-del sender@example.com recipient@example.net
sudo sentinelmilter --whitelist-del sender@example.com '*'
sudo systemctl start sentinelmilter
```

The wildcard deletes that sender's entries for every local recipient.

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

## License

SentinelMilter is available under the [MIT License](LICENSE).
