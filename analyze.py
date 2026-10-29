"""Analyse one email from the command line.

Examples:
    python analyze.py samples/phish_paypal.eml
    python analyze.py --text "Dear customer, verify your account at http://paypa1.com/login"
    python analyze.py --json samples/bec_wire.eml
    pbpaste | python analyze.py -          (paste from clipboard on a Mac)
"""

import argparse
import json
import sys

from phishguard.pipeline import PhishGuardPipeline

AGENT_ORDER = ["content", "url", "sender", "attachment", "social"]


def bar(score, width=20):
    filled = int(round(score * width))
    return "#" * filled + "." * (width - filled)


def print_report(report):
    fusion = report["fusion"]
    email = report["email"]
    print("=" * 64)
    print("VERDICT: " + report["verdict"] + "   risk " + str(fusion["risk_percent"]) + "%   spam " +
          str(round(100 * fusion["spam_probability"])) + "%")
    if fusion["bec_tier"] > 0:
        print("Business Email Compromise pattern, tier " + str(fusion["bec_tier"]))
    print("=" * 64)
    if email["subject"]:
        print("Subject: " + email["subject"])
    if email["from"]:
        print("From:    " + email["display_name"] + " <" + email["from"] + ">")
    print()
    for name in AGENT_ORDER:
        agent = report["agents"][name]
        print(name.upper().ljust(11) + " " + bar(agent["score"]) + " " + str(round(100 * agent["score"])).rjust(3) + "%")
        for finding in agent["findings"]:
            print("    - " + finding)
    print()
    if fusion["reasons"]:
        print("Why:")
        for reason in fusion["reasons"]:
            print("  * " + reason)
    tags = report["threat_intel"]["mitre_attack"]
    if tags:
        print("\nMITRE ATT&CK:")
        for tag in tags:
            print("  " + tag["id"].ljust(10) + tag["name"] + " (" + tag["tactic"] + ")")
    print("\nWhat to do:")
    for step in report["threat_intel"]["recommendations"]:
        print("  - " + step)
    if fusion["limitations"]:
        print("\nNotes:")
        for note in fusion["limitations"]:
            print("  - " + note)


def main():
    parser = argparse.ArgumentParser(description="PhishGuard AI email analyser")
    parser.add_argument("path", nargs="?", help="path to .eml or text file, or - for stdin")
    parser.add_argument("--text", help="analyse this text directly")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = parser.parse_args()

    if args.text:
        raw = args.text.encode("utf-8")
    elif args.path == "-":
        raw = sys.stdin.buffer.read()
    elif args.path:
        with open(args.path, "rb") as handle:
            raw = handle.read()
    else:
        parser.error("give a file path, - for stdin, or --text")

    report = PhishGuardPipeline().analyze_raw(raw)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
