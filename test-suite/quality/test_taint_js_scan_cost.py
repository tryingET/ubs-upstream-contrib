#!/usr/bin/env python3
"""JS taint cost stays linear in long callback bodies (GH #156).

The taint engine hands each expression, with its calls blanked, to
assignment_sources; for `describe(..., () => { ... })` that is the whole
test body as one run of spaces. ROUTE_PARAM_OBJECT's `^\\s*\\(?\\s*` split
such a run N ways on every failed match, so single Jest files hit the 300 s
module timeout. Measured here: the 30k-blank match takes ~2 ms (old: ~20 s,
bound 1 s) and the Jest-shaped file 0.5 s (old: 71.5 s, bound 30 s).
"""
from __future__ import annotations

import sys
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import taint_js  # noqa: E402
from ubs_core.registry import RunContext  # noqa: E402


class RouteParamObjectTests(unittest.TestCase):
    def test_accepts_the_same_forms(self) -> None:
        for expr in ("params", "  params  ", "(params)", "( params )", "await params",
                     "(await params)", "context.params", "(await context.params)",
                     "PARAMS", "(params", "params)"):
            with self.subTest(expr=expr):
                match = taint_js.ROUTE_PARAM_OBJECT.match(expr)
                self.assertIsNotNone(match)
                self.assertIn(match.group(1).lower(), {"params", "context.params"})
        for expr in ("params.id", "myparams", "params x", "await", "()", ""):
            with self.subTest(expr=expr):
                self.assertIsNone(taint_js.ROUTE_PARAM_OBJECT.match(expr))

    def test_failed_match_is_linear_in_whitespace(self) -> None:
        # ~2 ms linear; the quadratic form took ~9 s at 20k, so a regression
        # fails here within seconds instead of hanging the suite.
        blank = " " * 30_000
        for label, expr in (("blank", blank), ("trailing", "params" + blank + "x"),
                            ("paren", "(" + blank + "x")):
            with self.subTest(case=label):
                started = time.perf_counter()
                self.assertIsNone(taint_js.ROUTE_PARAM_OBJECT.match(expr))
                self.assertLess(time.perf_counter() - started, 1.0)


class JestShapedFileCostTests(unittest.TestCase):
    def test_long_describe_body_scans_in_bounded_time(self) -> None:
        lines = ["describe('orders', () => {"]
        for index in range(120):
            lines += [
                f"  it('case {index}', async () => {{",
                f"    const pattern = /^\\s*private async task{index}\\b/;",
                f"    const rows = await db.query('SELECT * FROM t WHERE id = $1', [{index}]);",
                "    expect(pattern.test(rows[0].src)).toBe(true);",
                "  });",
            ]
        lines.append("});")
        with tempfile.TemporaryDirectory(prefix="taint-js-cost-") as tmp:
            path = Path(tmp) / "orders.test.ts"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            started = time.perf_counter()
            findings = list(taint_js.run(RunContext(lang="javascript", files=[path])))
            elapsed = time.perf_counter() - started
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 30.0, f"taint_js took {elapsed:.1f}s on {len(lines)} lines")


@unittest.skipUnless(sys.platform.startswith("linux"), "GNU time reports peak RSS in KiB")
class LoopStateConvergenceTests(unittest.TestCase):
    def run(self, result=None):
        case = "c6-loop-pending-heap-summary"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        result = super().run(result)
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in (*result.failures, *result.errors))
        print(f"[{case}] {'FAIL' if failed else 'PASS'} "
              f"({time.perf_counter() - started:.2f}s)", flush=True)
        return result

    def test_pending_heap_calls_do_not_reset_loop_fixed_point(self) -> None:
        case = "c6-loop-pending-heap-summary"
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        loops = (
            ("for-of", "for (const value of values) {", "}"),
            ("for", "for (let i = 0; flag; i++) {", "}"),
            ("while", "while (flag) {", "}"),
            ("do", "do {", "} while (flag);"),
        )
        for label, opening, closing in loops:
            with self.subTest(loop=label):
                scratch = tempfile.mkdtemp(prefix=case + "-", dir=artifacts)
                path = Path(scratch) / "handler.ts"
                source = "\n".join([
                    "function context() { return {options: ['safe'], nested: {safe: 'clean'}}; }",
                    "function verify(box) { if (flag) { throw box; } return box; }",
                    "const values = [req.query.html];",
                    "try {",
                    opening,
                    "  const box = {html: req.query.html, context: context()};",
                    "  verify(box);",
                    "  document.body.innerHTML = box.html;",
                    "  document.body.innerHTML = box.context.nested.safe;",
                    closing,
                    "} catch (error) {",
                    "  document.body.innerHTML = error.html;",
                    "  document.body.innerHTML = error.context.nested.safe;",
                    "}",
                ])
                path.write_text(source + "\n", encoding="utf-8")
                env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR))
                command = [sys.executable, "-c",
                           "import json, sys; from pathlib import Path; "
                           "from ubs_core.analyzers.taint_js import scan_file_findings; "
                           "print(json.dumps([(rule, line) for rule, line, _, _ "
                           "in scan_file_findings(Path(sys.argv[1]))]))", str(path)]
                try:
                    result = subprocess.run(command, capture_output=True, text=True,
                                            env=env, timeout=10)
                except subprocess.TimeoutExpired as exc:
                    self.fail(f"{label} did not converge: {source}\n"
                              f"stdout={exc.stdout!r}\nstderr={exc.stderr!r}")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                try:
                    findings = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"{label} returned invalid JSON: {exc}\n"
                              f"stdout={result.stdout}\nstderr={result.stderr}")
                self.assertEqual(findings, [
                    ["js.taint.xss", 8], ["js.taint.xss", 12],
                ], source + "\n" + result.stdout + result.stderr)


class LoopExitConvergenceTests(unittest.TestCase):
    """Loops over a freshly allocated iterable whose body never falls through.

    Feature: the loop fixed point keeps the state it already reached
      Background: evaluating the loop header allocates on the current state,
        and a body that always returns, throws, breaks or waits on a pending
        summary yields no normal output. A join of entry and that output alone
        discards the header's allocations, so it never equals the current
        state; the solver then alternates forever (a module timeout) or stops
        on the entry state and loses the loop's facts.
      Scenario: the body leaves by return, throw or break; a body awaits a
        method still being summarized; the iterable comes from another module.
        Given such a loop that feeds a tainted element to a DOM sink,
        When taint_js analyzes it,
        Then it finishes within the ten-second deadline
        And it reports exactly that sink.
    """

    CASE = "ak6781-loop-exit-fresh-iterable"
    COLLECT = "function collect(input) { const items = [input]; return items; }"
    SINGLE = (
        ("return", [COLLECT,
                    "function first(req) {",
                    "  for (const item of collect(req.query.html)) {",
                    "    document.body.innerHTML = item;",
                    "    return item;",
                    "  }",
                    "  return '';",
                    "}"], [["js.taint.xss", 4]]),
        ("throw", [COLLECT,
                   "function first(req) {",
                   "  for (const item of collect(req.query.html)) {",
                   "    document.body.innerHTML = item;",
                   "    throw new Error(item);",
                   "  }",
                   "}"], [["js.taint.xss", 4]]),
        ("break", [COLLECT,
                   "function first(req) {",
                   "  let found = '';",
                   "  for (const item of collect(req.query.html)) {",
                   "    found = item;",
                   "    break;",
                   "  }",
                   "  document.body.innerHTML = found;",
                   "}"], [["js.taint.xss", 8]]),
        ("pending-method", [COLLECT,
                            "class Healer {",
                            "  async check(value) { return value.length > 3; }",
                            "  async first(req) {",
                            "    for (const item of collect(req.query.html)) {",
                            "      const ok = await this.check(item);",
                            "      if (!ok) document.body.innerHTML = item;",
                            "    }",
                            "  }",
                            "}"], [["js.taint.xss", 7]]),
    )

    def run(self, result=None):
        started = time.perf_counter()
        print(f"[{self.CASE}] RUN", flush=True)
        result = super().run(result)
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in (*result.failures, *result.errors))
        print(f"[{self.CASE}] {'FAIL' if failed else 'PASS'} "
              f"({time.perf_counter() - started:.2f}s)", flush=True)
        return result

    def analyze(self, label: str, script: str, paths: list[Path]) -> list:
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR))
        command = [sys.executable, "-c", script, *map(str, paths)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=10)
        except subprocess.TimeoutExpired as exc:
            self.fail(f"{label} did not converge within 10 s\n"
                      f"stdout={exc.stdout!r}\nstderr={exc.stderr!r}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"{label} returned invalid JSON: {exc}\n"
                      f"stdout={result.stdout}\nstderr={result.stderr}")

    def scratch(self) -> Path:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=self.CASE + "-", dir=artifacts))

    def test_loops_that_never_fall_through_converge_and_keep_their_facts(self) -> None:
        script = ("import json, sys; from pathlib import Path; "
                  "from ubs_core.analyzers.taint_js import scan_file_findings; "
                  "print(json.dumps([(rule, line) for rule, line, _, _ "
                  "in scan_file_findings(Path(sys.argv[1]))]))")
        for label, lines, expected in self.SINGLE:
            with self.subTest(exit=label):
                path = self.scratch() / "handler.js"
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                findings = self.analyze(label, script, [path])
                self.assertEqual(findings, expected, "\n".join(lines))

    def test_a_loop_over_an_imported_function_converges_across_modules(self) -> None:
        scratch = self.scratch()
        dependency, importer = scratch / "collect.mjs", scratch / "first.mjs"
        dependency.write_text(f"export {self.COLLECT}\n", encoding="utf-8")
        importer.write_text("\n".join([
            "import { collect } from './collect.mjs';",
            "export function first(req) {",
            "  for (const item of collect(req.query.html)) {",
            "    document.body.innerHTML = item;",
            "    return item;",
            "  }",
            "  return '';",
            "}",
        ]) + "\n", encoding="utf-8")
        script = ("import json, sys; from pathlib import Path; "
                  "from ubs_core.analyzers.taint_js import run; "
                  "from ubs_core.registry import RunContext; "
                  "files = [Path(arg) for arg in sys.argv[1:]]; "
                  "print(json.dumps(sorted([finding['rule'], Path(finding['path']).name, "
                  "finding['line']] for finding in run(RunContext(lang='javascript', files=files)))))")
        findings = self.analyze("cross-module", script, [dependency, importer])
        self.assertEqual(findings, [["javascript.taint.xss", "first.mjs", 4]])


class ProjectMemoryTests(unittest.TestCase):
    def test_400k_line_scan_preserves_findings_below_200_mib(self) -> None:
        self.check_project(connected=False)

    def test_400k_connected_scan_preserves_findings_below_200_mib(self) -> None:
        self.check_project(connected=True)

    def check_project(self, *, connected: bool) -> None:
        case = "c6-connected-source-memory" if connected else "c6-source-memory"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / case
        artifacts.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix="corpus-", dir=artifacts) as tmp:
                root = Path(tmp)
                sources = root / "sources"
                sources.mkdir()
                for index in range(400):
                    body = ([f"import './part_{max(0, index - 1):04d}';"]
                            if connected else [])
                    body += ["export function accumulate(value: number) {",
                             "  let result = value;"]
                    body.extend(["  result = result + 1;"] * (991 if connected else 992))
                    body += ["  return result;", "}"]
                    if index in (0, 399):
                        body += ["export function handle(req, res) {",
                                 "  const html = req.query.html;",
                                 "  res.send(html);", "}"]
                    else:
                        body += ["export function handle(req, res) {",
                                 "  const html = 'constant response';",
                                 "  res.send(html);", "}"]
                    self.assertEqual(len(body), 1000)
                    (sources / f"part_{index:04d}.ts").write_text(
                        "\n".join(body) + "\n", encoding="utf-8")
                env = os.environ.copy()
                env.update(UBS_NO_CACHE="1", UBS_NO_AUTO_UPDATE="1", UBS_PROFILE="1")
                peak = artifacts / "peak-rss-kib.txt"
                with (artifacts / "result.json").open("w", encoding="utf-8") as stdout, \
                        (artifacts / "stderr.log").open("w", encoding="utf-8") as stderr:
                    result = subprocess.run(
                        ["/usr/bin/time", "-f", "%M", "-o", str(peak),
                         str(REPO_ROOT / "ubs"), str(sources), "--only=js", "--ci", "--format=json"],
                        cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=300,
                    )
                diagnostic = (artifacts / "stderr.log").read_text(encoding="utf-8")
                doc = json.loads((artifacts / "result.json").read_text(encoding="utf-8"))
                self.assertEqual(result.returncode, 1, diagnostic)
                self.assertEqual(doc["status"], "ok", diagnostic)
                self.assertEqual(doc["failed_modules"], [], diagnostic)
                tainted = [(Path(f["file"]).name, f["line"]) for f in doc["findings"]
                           if f["rule_id"] == "javascript.taint.xss"]
                self.assertEqual(sorted(tainted), [("part_0000.ts", 999), ("part_0399.ts", 999)], diagnostic)
                self.assertEqual(doc["totals"]["critical"], 2, diagnostic)
                self.assertEqual(doc["totals"]["warning"], 0, diagnostic)
                self.assertEqual(doc["totals"]["files"], 400, diagnostic)
                self.assertEqual(doc["profile"]["cache_hits"], 0, diagnostic)
                rss_kib = int(peak.read_text(encoding="utf-8").splitlines()[-1])
                self.assertLess(rss_kib, 200 * 1024,
                                f"400K-line scan peaked at {rss_kib / 1024:.1f} MiB\n{diagnostic}")
        except Exception:
            print(f"[{case}] FAIL ({time.perf_counter() - started:.2f}s)", flush=True)
            for name in ("result.json", "stderr.log"):
                artifact = artifacts / name
                if artifact.exists():
                    print(f"{name}:\n{artifact.read_text(encoding='utf-8')}", flush=True)
            raise
        print(f"[{case}] PASS ({time.perf_counter() - started:.2f}s, {rss_kib / 1024:.1f} MiB)", flush=True)


if __name__ == "__main__":
    unittest.main()
