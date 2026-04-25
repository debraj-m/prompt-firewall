import argparse, re, sys
PATTERNS = [
    ('OPENAI_KEY', re.compile(r'sk-[A-Za-z0-9_-]{20,}')),
    ('GITHUB_TOKEN', re.compile(r'gh[pousr]_[A-Za-z0-9_]{20,}')),
    ('AWS_KEY', re.compile(r'AKIA[0-9A-Z]{16}')),
    ('EMAIL', re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')),
    ('PHONE', re.compile(r'(?<!\d)(?:\+?\d[\d .()-]{8,}\d)(?!\d)')),
    ('SECRET_ASSIGNMENT', re.compile(r'(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s]+')),
]

def redact(text):
    for label, pattern in PATTERNS:
        text = pattern.sub(f'[{label}_REDACTED]', text)
    return text

def main():
    parser = argparse.ArgumentParser(description='Redact sensitive text before AI prompts.')
    parser.add_argument('file', nargs='?')
    args = parser.parse_args()
    text = open(args.file, encoding='utf-8').read() if args.file else sys.stdin.read()
    print(redact(text), end='' if text.endswith('\n') else '\n')

if __name__ == '__main__':
    main()
