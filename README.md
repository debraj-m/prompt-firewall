# Prompt Firewall

Stop leaking secrets into AI prompts.

Prompt Firewall reads text, redacts common secrets and personal data, and prints safer text.

## Usage

```bash
prompt-firewall < notes.txt
echo "email me at test@example.com" | prompt-firewall
```
