# SentinelMilter Operating Guide

Using the supplied default configuration, SentinelMilter will use AI to identify
unwanted spam and scam email, including threats concealed in images, and provide
basic virus protection by blocking executable attachments. It will not scan
authenticated outbound email. It will initially monitor inbound email without
rejecting it, allowing you to confirm that its decisions are reliable before
enabling enforcement. Over time, it will learn and whitelist trusted email
senders, and identify and blacklist problematic sending IP addresses to reduce
false positives, false negatives, AI usage, and operating costs.

## Before you start

SentinelMilter's configuration file is `/etc/sentinelmilter/sentinelmilter.yaml`.
Edit it before starting the service, preserving its YAML indentation and using
spaces rather than tabs.

The email data used for classification is sent to the configured AI endpoint,
including selected headers, extracted message text, links, and qualifying inline
images. If email content must remain entirely private, use SentinelMilter with a
locally hosted AI server; see the Running AI locally section. If you use
OpenRouter, its Privacy settings include a Zero Data Retention option that
restricts routing to providers with a zero-data-retention policy.

SentinelMilter requires access to a compatible AI model. The supplied
configuration uses OpenRouter and must be given a valid API key before the
service is started. If the example model is no longer available, choose a
current compatible model.

https://openrouter.ai

SentinelMilter can use a locally operated llama.cpp server for AI functionality.
Set the endpoint and model in the configuration to match your local server. The
model must support image input if you want SentinelMilter to examine email whose
message is contained in an image.

The supplied detection prompt at
`/etc/sentinelmilter/detection-prompt.txt` and the example settings have been
tested with the model named in the configuration. Different models may interpret
the prompt or confidence scale differently, so test any replacement model before
allowing it to reject live email.

## Start in monitor mode

The default `monitor` mode analyses email and logs the action SentinelMilter
would recommend, but allows the message through. Leave it in this mode while you
send representative test messages and observe real mail traffic.

Review the journal regularly:

```sh
journalctl -u sentinelmilter --since yesterday --no-pager -o cat
```

Pay particular attention to legitimate messages classified as spam or scam,
unwanted messages classified as legitimate, endpoint failures, and unusually
slow responses. Adjust the detection prompt, model, or rejection threshold when
the results consistently show that a change is needed.

## Enable enforcement

When monitor-mode results are satisfactory, change the mode to `enforce` and
restart SentinelMilter. It will then reject unwanted messages that meet the
configured confidence threshold and block prohibited executable attachments.

Continue reviewing decisions after enabling enforcement. AI classification is
not perfectly deterministic, and changes made by an AI provider can alter a
model's behaviour even when the configured model name remains unchanged.

The supplied configuration accepts mail if AI analysis fails. This avoids mail
loss when the endpoint is unavailable. If you prefer the sending server to try
again later, change the configured AI failure action to `tempfail`.

## Trusted mail and adaptive filtering

Authenticated outbound mail is not scanned by default. SentinelMilter uses
accepted outbound mail to learn which external addresses each local user
corresponds with. These addresses are immediately whitelisted and can bypass
future scanning when the configured authentication requirements are met.
SentinelMilter can also learn inbound senders that repeatedly receive a
high-confidence legitimate classification and pass the configured authentication
checks.

This reduces cost and avoids repeatedly classifying routine mail. Entire email
domains can also be whitelisted in the configuration file. The supplied example
whitelists `amazon.com` and `amazon.co.uk`, allowing email from those sources to
bypass scanning when trusted, aligned DKIM authentication passes. Merely forging
an Amazon address therefore does not bypass filtering.

When SentinelMilter rejects unwanted mail, it records the sending IP address.
Repeated attempts can then be rejected without another AI request, and persistent
offenders receive longer blocks. Legitimate traffic gradually reduces an IP's
negative reputation. In the supplied configuration, every three legitimate
messages removes one recorded spam or scam strike, although an active block
continues until it expires. Configured shared mail providers are protected from
automatic blacklisting.

The learned correspondent and IP reputation data is kept in
`/var/lib/sentinelmilter` and survives service restarts. Back up this directory
if you want to preserve the learned state when moving the service to another
machine.

## Running AI locally

A local model keeps sensitive email content within your own infrastructure
instead of sending it to a hosted AI provider, providing the strongest privacy
option. It also removes per-message API charges, but requires suitable hardware
and ongoing administration. Choose a model that follows structured instructions
reliably and returns consistent classifications. Vision support is required to
analyse scams presented as images.

The default Qwen3.6-35B-A3B model has relatively modest hardware requirements
and can perform very well locally when the mail server is fitted with a suitable
GPU.

Allow enough AI timeout for the slowest messages you expect to process. Large
messages and image analysis generally take longer than short text messages. Also
keep the MTA's Milter timeout longer than SentinelMilter's AI timeout so that the
MTA does not abandon the request while analysis is still running.

Before adopting a local model, replay a representative collection of legitimate,
spam, and scam messages against a separate SentinelMilter test instance. Compare
both accuracy and response time with the hosted model before switching production
traffic.

## Routine operation

Keep the service, detection prompt, and model under review as the mail you receive
changes. Check the journal for rejected mail, endpoint errors, attachment-policy
decisions, and changes in classification quality. After changing the prompt,
model, confidence threshold, or filtering policy, repeat the saved-message tests
before restarting production.

Validate configuration changes before applying them:

```sh
sentinelmilter --config /etc/sentinelmilter/sentinelmilter.yaml --check-config
```
