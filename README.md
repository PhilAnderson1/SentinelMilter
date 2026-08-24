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
