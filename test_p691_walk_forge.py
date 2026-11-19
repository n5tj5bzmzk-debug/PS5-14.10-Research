#!/usr/bin/env python3
"""Regression checks for p691's configurable forged-vtable diagnostics.

These checks only parse and inspect the probe source; they never start a
browser or contact a console. They protect the query parameters and measured
vtable deltas that are easy to silently regress during probe edits.
"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase13_webkit" / "p691-walk-forge-fixed.html"
SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)


class P691WalkForgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PROBE.read_text(encoding="utf-8")

    def test_safe_poison_slot_is_the_documented_default(self):
        self.assertRegex(self.source, r"PK=qint\('pk',9\)")

    def test_pk_controls_one_vtable_slot(self):
        self.assertIn("(jv===PK)?0x4141414141414141n:G_TRY", self.source)

    def test_slot_two_delta_matches_the_measured_value(self):
        self.assertIn("S2=VP-0x324C3D8n", self.source)
        self.assertNotIn("S2=VP-0x324C3DD8n", self.source)

    def test_s0_minus_one_is_not_reported_as_a_ret_gadget(self):
        self.assertIn("GADGET-s0m1=", self.source)
        self.assertNotIn("GADGET-ret=", self.source)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_inline_script_parses_as_a_classic_script(self):
        scripts = [match.group(1) for match in SCRIPT_RE.finditer(self.source)
                   if match.group(1).strip()]
        self.assertTrue(scripts)
        with tempfile.TemporaryDirectory() as tmp:
            for index, script in enumerate(scripts):
                path = Path(tmp) / f"p691-{index}.js"
                path.write_text(script, encoding="utf-8", newline="\n")
                result = subprocess.run(
                    ["node", "--check", str(path)], capture_output=True,
                    text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
