from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern[str]
    description: str


DETECTORS = [
    Detector(
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "OpenAI-style API key",
    ),
    Detector(
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        "GitHub personal access token",
    ),
    Detector(
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS access key ID",
    ),
    Detector(
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "Slack token",
    ),
    Detector(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "JSON Web Token",
    ),
    Detector(
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "Email address",
    ),
    Detector(
        "credit_card",
        re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
        "Possible payment card number",
    ),
    Detector(
        "phone",
        re.compile(r"(?<!\d)(?:\+?\d[\d .()-]{8,}\d)(?!\d)"),
        "Phone number",
    ),
    Detector(
        "secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|token|password|passwd|secret|client_secret)"
            r"\s*[:=]\s*['\"]?[^'\"\s]+"
        ),
        "Secret-looking key/value assignment",
    ),
]


def luhn_valid(value: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", value)]
    if len(digits) < 13:
        return False

    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def digit_count(value: str) -> int:
    return len(re.sub(r"\D", "", value))


def active_detectors(names: Iterable[str] | None = None) -> list[Detector]:
    if not names:
        return DETECTORS

    requested = set(names)
    available = {detector.name: detector for detector in DETECTORS}
    unknown = sorted(requested - set(available))
    if unknown:
        raise ValueError(f"Unknown detector(s): {', '.join(unknown)}")
    return [available[name] for name in requested]


def find_matches(text: str, detectors: Iterable[Detector] | None = None) -> list[dict]:
    findings = []
    for detector in detectors or DETECTORS:
        for match in detector.pattern.finditer(text):
            value = match.group(0)
            if detector.name == "credit_card" and not luhn_valid(value):
                continue
            if detector.name == "phone" and (
                luhn_valid(value) or digit_count(value) > 12
            ):
                continue

            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                {
                    "type": detector.name,
                    "description": detector.description,
                    "line": line,
                    "start": match.start(),
                    "end": match.end(),
                    "preview": preview(value),
                }
            )
    return sorted(findings, key=lambda item: (item["start"], item["end"]))


def preview(value: str) -> str:
    compact = value.strip()
    if len(compact) <= 8:
        return "*" * len(compact)
    return f"{compact[:3]}...{compact[-3:]}"


def replacement_for(detector_name: str, replacement: str) -> str:
    if "{type}" in replacement:
        return replacement.format(type=detector_name)
    return replacement


def redact(
    text: str,
    detectors: Iterable[Detector] | None = None,
    replacement: str = "[{type}_REDACTED]",
) -> str:
    output = text
    for detector in detectors or DETECTORS:
        def replace(match: re.Match[str]) -> str:
            value = match.group(0)
            if detector.name == "credit_card" and not luhn_valid(value):
                return value
            if detector.name == "phone" and (
                luhn_valid(value) or digit_count(value) > 12
            ):
                return value
            return replacement_for(detector.name, replacement)

        output = detector.pattern.sub(replace, output)
    return output


def read_text(path: str | None) -> str:
    if not path or path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def write_text(path: str | None, text: str) -> None:
    if not path or path == "-":
        print(text, end="" if text.endswith("\n") else "\n")
        return
    Path(path).write_text(text, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Redact secrets and personal data before sending text to AI tools."
    )
    subparsers = parser.add_subparsers(dest="command")

    redact_parser = subparsers.add_parser("redact", help="Redact sensitive values.")
    redact_parser.add_argument("file", nargs="?", help="Input file. Defaults to stdin.")
    redact_parser.add_argument("-o", "--output", help="Write redacted text to a file.")
    redact_parser.add_argument(
        "--replacement",
        default="[{type}_REDACTED]",
        help="Replacement text. Use {type} for detector name.",
    )
    redact_parser.add_argument(
        "--only",
        action="append",
        choices=[detector.name for detector in DETECTORS],
        help="Run only the named detector. Can be used more than once.",
    )

    scan_parser = subparsers.add_parser("scan", help="Report sensitive values.")
    scan_parser.add_argument("file", nargs="?", help="Input file. Defaults to stdin.")
    scan_parser.add_argument("--json", action="store_true", help="Print JSON findings.")
    scan_parser.add_argument(
        "--fail-on-detect",
        action="store_true",
        help="Exit with code 1 if anything sensitive is detected.",
    )
    scan_parser.add_argument(
        "--only",
        action="append",
        choices=[detector.name for detector in DETECTORS],
        help="Run only the named detector. Can be used more than once.",
    )

    parser.add_argument(
        "--list-detectors",
        action="store_true",
        help="List available detectors and exit.",
    )
    return parser


def list_detectors() -> None:
    for detector in DETECTORS:
        print(f"{detector.name}: {detector.description}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_detectors:
        list_detectors()
        return

    command = args.command or "redact"
    detectors = active_detectors(getattr(args, "only", None))
    text = read_text(getattr(args, "file", None))

    if command == "scan":
        findings = find_matches(text, detectors)
        if args.json:
            print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
        else:
            if not findings:
                print("No sensitive values detected.")
            for finding in findings:
                print(
                    f"{finding['type']} line {finding['line']}: "
                    f"{finding['preview']}"
                )
        if args.fail_on_detect and findings:
            raise SystemExit(1)
        return

    replacement = getattr(args, "replacement", "[{type}_REDACTED]")
    output = getattr(args, "output", None)
    redacted = redact(text, detectors, replacement=replacement)
    write_text(output, redacted)


if __name__ == "__main__":
    main()
