"""Feature: an authorization or token *scope* is metadata, not secret material.

The constant-time comparison analyzers treat ``authorization`` as a strong
secret term unless the next identifier term is schema/metadata vocabulary
(``signatureFormat``, ``credentialType``, ``jwtHeader``; GH #85). ``scope`` was
missing from that vocabulary, so a public boundary label such as
``handoff.AuthorizationScope != "local_clone_only"`` was reported as a critical
timing-unsafe secret comparison. A scope names what a credential may do; it
is not the credential, and comparing it with ``==`` leaks nothing.

Scenarios are written Given/When/Then; each outline runs once per analyzer.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import ctcompare_go  # noqa: E402
from ubs_core.analyzers import ctcompare_js  # noqa: E402
from ubs_core.analyzers import ctcompare_py  # noqa: E402
from ubs_core.analyzers import ctcompare_rust  # noqa: E402


def _go_lines(source: str) -> list[int]:
    with tempfile.TemporaryDirectory(prefix="ubs_ct_scope_go_") as tmp:
        path = Path(tmp) / "handoff.go"
        path.write_text(source, encoding="utf-8")
        return sorted(line for _rel, line, _code in ctcompare_go.scan_file(path, Path(tmp)))


def _js_lines(source: str) -> list[int]:
    with tempfile.TemporaryDirectory(prefix="ubs_ct_scope_js_") as tmp:
        path = Path(tmp) / "handoff.js"
        path.write_text(source, encoding="utf-8")
        return sorted(line for _rel, line, _code in ctcompare_js.scan_file(path, Path(tmp)))


def _py_lines(source: str) -> list[int]:
    with tempfile.TemporaryDirectory(prefix="ubs_ct_scope_py_") as tmp:
        path = Path(tmp) / "handoff.py"
        path.write_text(source, encoding="utf-8")
        issues: list = []
        ctcompare_py.analyze(path, issues)
        return sorted(line for _path, line, _code in issues)


def _rust_lines(source: str) -> list[int]:
    return sorted(line for line, _code in ctcompare_rust.scan_file(source))


# Examples: language | scan | scope comparisons (clean) | secret comparison (still critical)
SCOPE_EXAMPLES = {
    "go": (
        _go_lines,
        "package handoff\n"
        "\n"
        "type Intent struct{ AuthorizationScope string }\n"
        "\n"
        "func IsLocalOnly(h Intent, tokenScope string) bool {\n"
        "\tif h.AuthorizationScope != \"local_clone_only\" {\n"
        "\t\treturn false\n"
        "\t}\n"
        "\treturn tokenScope == \"read\"\n"
        "}\n",
    ),
    "js": (
        _js_lines,
        "function isLocalOnly(handoff, tokenScope) {\n"
        "  if (handoff.authorizationScope !== \"local_clone_only\") {\n"
        "    return false;\n"
        "  }\n"
        "  return tokenScope === \"read\";\n"
        "}\n",
    ),
    "python": (
        _py_lines,
        "def is_local_only(handoff, token_scope):\n"
        "    if handoff.authorization_scope != \"local_clone_only\":\n"
        "        return False\n"
        "    return token_scope == \"read\"\n",
    ),
    "rust": (
        _rust_lines,
        "pub fn is_local_only(handoff: &Intent, token_scope: &str) -> bool {\n"
        "    if handoff.authorization_scope != \"local_clone_only\" {\n"
        "        return false;\n"
        "    }\n"
        "    token_scope == \"read\"\n"
        "}\n",
    ),
}

SECRET_EXAMPLES = {
    "go": (
        _go_lines,
        "package handoff\n"
        "\n"
        "func Check(authorizationToken string, expected string) bool {\n"
        "\treturn authorizationToken == expected\n"
        "}\n",
        [4],
    ),
    "js": (
        _js_lines,
        "function check(authorizationToken, expected) {\n"
        "  return authorizationToken === expected;\n"
        "}\n",
        [2],
    ),
    "python": (
        _py_lines,
        "def check(authorization_token, expected):\n"
        "    return authorization_token == expected\n",
        [2],
    ),
    "rust": (
        _rust_lines,
        "pub fn check(authorization_token: &str, expected: &str) -> bool {\n"
        "    authorization_token == expected\n"
        "}\n",
        [2],
    ),
}


class AuthorizationScopeIsMetadataFeature(unittest.TestCase):
    def test_scenario_scope_label_compared_with_a_literal_is_not_a_secret_compare(self) -> None:
        for language, (scan, source) in SCOPE_EXAMPLES.items():
            with self.subTest(language=language):
                # Given code comparing an authorization or token scope label with ==/!=
                # When the constant-time comparison analyzer scans it
                findings = scan(source)
                # Then no timing-unsafe secret comparison is reported
                self.assertEqual(findings, [], f"{language}: scope label flagged as secret")

    def test_scenario_authorization_token_is_still_a_secret_compare(self) -> None:
        for language, (scan, source, expected_lines) in SECRET_EXAMPLES.items():
            with self.subTest(language=language):
                # Given code comparing an authorization token with ==
                # When the constant-time comparison analyzer scans it
                findings = scan(source)
                # Then the timing-unsafe secret comparison is still reported
                self.assertEqual(findings, expected_lines, f"{language}: secret compare missed")


if __name__ == "__main__":
    unittest.main()
