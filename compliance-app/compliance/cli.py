"""Command-line entry point: score a local JSON file of Wazuh SCA results.

Usage: python -m compliance <results.json>

The file must contain a JSON list of SCA documents, or a single document.
"""

import argparse
import json
import sys

from .scoring import compute_compliance_score, compute_framework_scores


def _percent(value):
    return "N/A" if value is None else f"{value:.2f}%"


def format_score(score, frameworks=None):
    lines = [
        f"Passed:          {score['passed']}",
        f"Failed:          {score['failed']}",
        f"Not applicable:  {score['not_applicable']}",
        f"Unknown:         {score['unknown']}",
        f"Pass percentage: {_percent(score['pass_percentage'])}",
    ]
    if frameworks:
        lines += ["", "By framework:",
                  f"  {'Framework':<20} {'Passed':>6} {'Failed':>6} {'Not app.':>8} {'Unknown':>7} {'Pass %':>8}"]
        for name, fw in frameworks.items():
            lines.append(f"  {name:<20} {fw['passed']:>6} {fw['failed']:>6} {fw['not_applicable']:>8} "
                         f"{fw['unknown']:>7} {_percent(fw['pass_percentage']):>8}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="compliance", description="Score Wazuh SCA results from a JSON file.")
    parser.add_argument("path", help="path to a JSON file of SCA check documents")
    parser.add_argument("--json-output", metavar="PATH",
                        help="also save overall and per-framework scores to this JSON file")
    args = parser.parse_args(argv)

    try:
        with open(args.path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = [data]
        score = compute_compliance_score(data)
        frameworks = compute_framework_scores(data)
    except OSError as e:
        print(f"error: cannot read {args.path}: {e.strerror or e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON in {args.path}: {e}", file=sys.stderr)
        return 1
    except (TypeError, ValueError) as e:
        print(f"error: invalid SCA results in {args.path}: {e}", file=sys.stderr)
        return 1

    print(format_score(score, frameworks))

    if args.json_output:
        report = {"overall": score, "frameworks": frameworks}
        try:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
                f.write("\n")
        except OSError as e:
            print(f"error: cannot write JSON report to {args.json_output}: {e.strerror or e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
