"""Feature: fetch() without an AbortSignal is found in formatter-wrapped chains.

Prettier wraps a long `window.fetch(url).then(...)` chain as

    return window
      .fetch(url)
      .then((response) => response.text());

`fetch_start_re` requires that `fetch(` is not preceded by `.` (so `api.fetch(`
method calls are not global fetches), and the receiver `window` sits on the
previous line, so the wrapped call was not recognised at all. The style pass
659c0f9d wrapped `loadAuditTrail` in test-suite/js/security/fetch-timeout-buggy.ts
this way, and js.security.fetch-abort findings on that fixture dropped from 3 to 2.

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

from ubs_core.analyzers import sec_fetch_abort  # noqa: E402


def finding_lines(source: str) -> list[int]:
    with tempfile.TemporaryDirectory(prefix="ubs_fetch_abort_") as tmp:
        path = Path(tmp) / "client.ts"
        path.write_text(source, encoding="utf-8")
        return [line for line, _sample in sec_fetch_abort.scan_file_findings(path)]


FLAGGED = {
    "window receiver on the previous line": (
        "export function load(id: string) {\n"
        "  return window\n"
        "    .fetch(`/api/${id}`)\n"
        "    .then((response) => response.text());\n"
        "}\n",
        [3],
    ),
    "globalThis receiver on the previous line": (
        "export function load(id: string) {\n"
        "  return globalThis\n"
        "    .fetch(`/api/${id}`);\n"
        "}\n",
        [3],
    ),
    "single-line window.fetch": (
        "export const load = (id: string) => window.fetch(`/api/${id}`);\n",
        [1],
    ),
}

CLEAN = {
    "wrapped call with a signal": (
        "export function load(id: string, signal: AbortSignal) {\n"
        "  return window\n"
        "    .fetch(`/api/${id}`, { signal })\n"
        "    .then((response) => response.text());\n"
        "}\n"
    ),
    "wrapped call with multi-line options carrying a signal": (
        "export function load(id: string, controller: AbortController) {\n"
        "  return window\n"
        "    .fetch(\n"
        "      `/api/${id}`,\n"
        "      { signal: controller.signal },\n"
        "    )\n"
        "    .then((response) => response.text());\n"
        "}\n"
    ),
    "method named fetch on another object": (
        "export function load(api: Client, id: string) {\n"
        "  return api\n"
        "    .fetch(`/api/${id}`);\n"
        "}\n"
    ),
}


class FetchAbortFormatterWrappedFeature(unittest.TestCase):
    def test_scenario_wrapped_global_fetch_without_signal_is_reported(self) -> None:
        for name, (source, expected) in FLAGGED.items():
            with self.subTest(example=name):
                # Given a global fetch without an AbortSignal, possibly wrapped across lines
                # When the fetch-abort analyzer scans the file
                lines = finding_lines(source)
                # Then the call is reported on the line holding `.fetch(`
                self.assertEqual(lines, expected, name)

    def test_scenario_wrapped_calls_with_a_signal_or_another_receiver_stay_clean(self) -> None:
        for name, source in CLEAN.items():
            with self.subTest(example=name):
                # Given a wrapped call that passes a signal, or a method named fetch on another object
                # When the fetch-abort analyzer scans the file
                lines = finding_lines(source)
                # Then nothing is reported
                self.assertEqual(lines, [], name)


if __name__ == "__main__":
    unittest.main()
