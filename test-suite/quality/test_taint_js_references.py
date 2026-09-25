"""Feature: JS taint only follows real references to a tainted variable.

`expr_has_tainted` matched a tainted name anywhere in an expression, so a
member access (`user.email`) or an object-literal key (`{ email: ... }`) that
merely shares the name of a tainted variable (`const { email } = req.body`)
counted as a use of it. That propagated taint into unrelated values and
reported them at sinks: `test-suite/frameworks/node/clean-api.js` (manifest
case js-node-clean) reports `req.body -> email -> token -> HTTP json send` for a
JWT built from `user.email` and returned with `res.json({ token, ... })`.

Scenarios are written Given/When/Then.
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

from ubs_core.analyzers import taint_js  # noqa: E402


def taint_findings(source: str) -> list[tuple[str, int]]:
    with tempfile.TemporaryDirectory(prefix="ubs_taint_js_refs_") as tmp:
        path = Path(tmp) / "handler.js"
        path.write_text(source, encoding="utf-8")
        return sorted((rule, line) for rule, line, _col, _desc in taint_js.scan_file_findings(path))


CLEAN_EXAMPLES = {
    "member access shares the tainted name": (
        "function login(req, res, user) {\n"
        "  const { email } = req.body;\n"
        "  const token = sign(user.email);\n"
        "  res.json({ token });\n"
        "}\n"
    ),
    "optional member access shares the tainted name": (
        "function login(req, res, user) {\n"
        "  const { email } = req.body;\n"
        "  const token = sign(user?.email);\n"
        "  res.json({ token });\n"
        "}\n"
    ),
    "object key shares the tainted name": (
        "function login(req, res, user) {\n"
        "  const { email } = req.body;\n"
        "  const token = sign({ id: user.id, email: user.address });\n"
        "  res.json({ token });\n"
        "}\n"
    ),
    "sink object key shares the tainted name": (
        "function reply(req, res) {\n"
        "  const { email } = req.body;\n"
        "  lookup(email);\n"
        "  res.send({ email: \"hidden\" });\n"
        "}\n"
    ),
}

TAINTED_EXAMPLES = {
    "direct use": (
        "function echo(req, res) {\n"
        "  const { email } = req.body;\n"
        "  res.send(email);\n"
        "}\n",
        [("js.taint.xss", 3)],
    ),
    "shorthand property": (
        "function echo(req, res) {\n"
        "  const { email } = req.body;\n"
        "  res.send({ email });\n"
        "}\n",
        [("js.taint.xss", 3)],
    ),
    "value of a same-named key": (
        "function echo(req, res) {\n"
        "  const { email } = req.body;\n"
        "  res.send({ email: email });\n"
        "}\n",
        [("js.taint.xss", 3)],
    ),
    "spread of the tainted object": (
        "function echo(req, res) {\n"
        "  const body = req.body;\n"
        "  res.send({ ...body });\n"
        "}\n",
        [("js.taint.xss", 3)],
    ),
    "ternary branch": (
        "function echo(req, res, ok) {\n"
        "  const { email } = req.body;\n"
        "  const shown = ok ? email : \"n/a\";\n"
        "  res.send(shown);\n"
        "}\n",
        [("js.taint.xss", 4)],
    ),
}


class TaintFollowsRealReferencesFeature(unittest.TestCase):
    def test_scenario_same_named_member_or_key_does_not_carry_taint(self) -> None:
        for name, source in CLEAN_EXAMPLES.items():
            with self.subTest(example=name):
                # Given a request field bound to `email` and unrelated code reusing that name
                #   as a member access or an object key
                # When the JS taint analyzer scans the handler
                findings = taint_findings(source)
                # Then no tainted flow is reported
                self.assertEqual(findings, [], name)

    def test_scenario_real_references_still_carry_taint(self) -> None:
        for name, (source, expected) in TAINTED_EXAMPLES.items():
            with self.subTest(example=name):
                # Given a request field bound to `email` that reaches a sink by a real reference
                # When the JS taint analyzer scans the handler
                findings = taint_findings(source)
                # Then the tainted flow is still reported at the sink
                self.assertEqual(findings, expected, name)


if __name__ == "__main__":
    unittest.main()
