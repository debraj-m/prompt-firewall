# Prompt Firewall

**Stop leaking secrets into AI prompts.**

Prompt Firewall is a tiny local-first CLI that redacts API keys, tokens, emails,
phone numbers, payment-card-looking values, and secret-looking assignments before
you paste text into ChatGPT, Claude, Gemini, Cursor, logs, tickets, or support
threads.

It is intentionally boring: no account, no server, no telemetry, no cloud call.
Just pipe text in and get safer text out.

## Why

AI tools make it effortless to paste logs, stack traces, `.env` snippets, chat
transcripts, customer messages, and bug reports into a model.

That convenience has a sharp edge: prompts often contain secrets.

Prompt Firewall gives you a fast local guardrail:

```bash
cat incident-notes.txt | prompt-firewall
```

## Install

```bash
git clone https://github.com/debraj-m/prompt-firewall.git
cd prompt-firewall
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick Start

Redact stdin:

```bash
echo "email test@example.com and use api_key=secret123" | prompt-firewall
```

Output:

```text
email [email_REDACTED] and use [secret_assignment_REDACTED]
```

Redact a file:

```bash
prompt-firewall redact debug.log
```

Write redacted output to a new file:

```bash
prompt-firewall redact debug.log --output debug.safe.log
```

Scan without modifying text:

```bash
prompt-firewall scan debug.log
```

Use in CI and fail if sensitive values are found:

```bash
prompt-firewall scan prompt.txt --fail-on-detect
```

JSON output:

```bash
prompt-firewall scan prompt.txt --json
```

Run only specific detectors:

```bash
prompt-firewall redact .env --only secret_assignment --only email
```

List detectors:

```bash
prompt-firewall --list-detectors
```

## Detectors

Prompt Firewall currently detects:

- OpenAI-style API keys
- GitHub personal access tokens
- AWS access key IDs
- Slack tokens
- JSON Web Tokens
- Email addresses
- Phone numbers
- Luhn-valid payment-card-looking values
- Secret-looking assignments such as `api_key=...`, `token=...`, `password=...`

The goal is practical protection, not perfect DLP. Always review sensitive
material before sharing it.

## Command Reference

Default behavior is `redact`:

```bash
prompt-firewall < file.txt
prompt-firewall redact file.txt
```

Custom replacement text:

```bash
prompt-firewall redact file.txt --replacement "[REDACTED]"
prompt-firewall redact file.txt --replacement "[{type}]"
```

Scan mode:

```bash
prompt-firewall scan file.txt
prompt-firewall scan file.txt --json
prompt-firewall scan file.txt --fail-on-detect
```

## Examples

Before:

```text
OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456
Contact me at debraj@example.com
Card: 4242 4242 4242 4242
```

After:

```text
[secret_assignment_REDACTED]
Contact me at [email_REDACTED]
Card: [credit_card_REDACTED]
```

## Local Checks

```bash
pip install -e .
python -m unittest discover -s tests
prompt-firewall --list-detectors
```

## Roadmap

- Config file for custom allowlists and project-specific detectors
- Pre-commit hook
- GitHub Action wrapper
- Markdown report mode
- More cloud-provider token detectors

## License

MIT. See [LICENSE](LICENSE).
