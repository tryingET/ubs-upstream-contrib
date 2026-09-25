"""Feature: buggy fixtures keep the bug their rule is meant to detect.

Directory-level manifest cases (js-core-buggy, js-module-buggy) only assert
totals, so a formatter or lint autofix that repairs an intentional bug in a
buggy fixture goes unnoticed as long as other findings keep the totals up.
The style pass 659c0f9d did that: it added rel="noopener" to
target-blank-buggy.tsx, parenthesised the ternary/nullish precedence bug in
ast-grep-rule-pack-coverage.ts(x), and turned two constant-pattern
`new RegExp('...')` calls in 12-regex-vulnerabilities.js into literals, which
left three calls and put the file under js.regex.dynamic-regexp's report
threshold (more than 3 per file).

Each example pins one fixture to the rule it exists for, with the minimum
number of findings the unformatted fixture produced.

Scenarios are written Given/When/Then.
"""
from __future__ import annotations

import collections
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Examples: fixture | --only | rule | minimum findings
FIXTURE_RULES = [
    ("test-suite/buggy/12-regex-vulnerabilities.js", "js", "js.regex.dynamic-regexp", 5),
    ("test-suite/js/buggy/ast-grep-rule-pack-coverage.ts", "js", "js.operator-precedence-ternary-nullish", 1),
    ("test-suite/js/buggy/ast-grep-rule-pack-coverage.tsx", "js", "js.operator-precedence-ternary-nullish", 1),
    ("test-suite/js/security/target-blank-buggy.tsx", "js", "js.security.jsx-target-blank", 1),
]


def rule_counts(fixture: str, only: str) -> collections.Counter:
    env = {**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1"}
    proc = subprocess.run(
        [str(REPO_ROOT / "ubs"), f"--only={only}", "--format=json", str(REPO_ROOT / fixture)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=180,
    )
    doc = json.loads(proc.stdout)
    counts: collections.Counter = collections.Counter()
    for scanner in doc.get("scanners", [doc]):
        for finding in scanner.get("findings") or []:
            counts[finding.get("rule")] += 1
    return counts


@unittest.skipUnless(shutil.which("ast-grep"), "ast-grep required for the JS/TS rule pack")
class BuggyFixturesKeepTheirBugFeature(unittest.TestCase):
    def test_scenario_each_buggy_fixture_still_triggers_its_rule(self) -> None:
        for fixture, only, rule, minimum in FIXTURE_RULES:
            with self.subTest(fixture=fixture, rule=rule):
                # Given a buggy fixture that exists to exercise one rule
                # When ubs scans that fixture alone
                counts = rule_counts(fixture, only)
                # Then the rule still fires at least as often as the unformatted fixture did
                self.assertGreaterEqual(counts[rule], minimum, f"{fixture}: {rule} {dict(counts)}")


if __name__ == "__main__":
    unittest.main()
