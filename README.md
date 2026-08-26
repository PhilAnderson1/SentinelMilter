# SentinelMilter

[![CI](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml/badge.svg)](https://github.com/PhilAnderson1/SentinelMilter/actions/workflows/ci.yml)

SentinelMilter is an AI-powered milter for efficiently and accurately identifying and rejecting unwanted email. SentinelMilter is compatible with OpenRouter or llama.cpp-type `v1/chat/completions` endpoints.

## Why SentinelMilter?

Traditional filters are good at detecting known senders, signatures, keywords, reputation signals, and statistical patterns. Scams, however, are often defined by meaning: what the sender claims, what they want the recipient to do, and how those elements combine. Attackers can change their wording, formatting, domains, and story while preserving the same underlying scam.

SentinelMilter adds an LLM-based semantic layer that can:

- Recognize a scam pattern even when its exact wording has not been seen before.
- Evaluate combinations of evidence, such as a claimed Microsoft alert paired with a sign-in link to an unrelated domain.
- Distinguish suspicious requests from legitimate receipts, account notifications, subscribed newsletters, and ongoing correspondence by considering the surrounding context.
- Compare visible link text with the actual destination preserved during HTML conversion.
- Apply user-defined unwanted-email patterns written in plain language instead of requiring complex regular expressions or code changes.
- Explain every classification with a confidence score and concise, evidence-based reasons.

This makes SentinelMilter particularly useful for identifying novel variations of phishing, extortion, advance-fee fraud, and unsolicited commercial outreach. Its role is to evaluate what a message is trying to persuade the recipient to believe or do.

AI complements rather than replaces deterministic mail-security controls. SPF, DKIM, DMARC, sender and URL reputation, antivirus scanning, blocklists, and conventional spam filters remain better suited to authentication, reputation, and malware detection. SentinelMilter combines their available results with the message's language and links to make a contextual decision.

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
smtpd_milters = unix:/run/sentinelmilter/sentinelmilter.sock
non_smtpd_milters = unix:/run/sentinelmilter/sentinelmilter.sock
milter_default_action = accept
milter_protocol = 6
```

The Postfix process must be able to access the socket directory. On installations where Postfix SMTP runs chrooted, expose the socket inside its chroot or use a loopback TCP listener with appropriate firewalling.

Logs are JSON records in the systemd journal. A successful decision records both `proposed_action` and `actual_action`, making monitor-mode evaluation explicit.

## License

SentinelMilter is available under the [MIT License](LICENSE).
