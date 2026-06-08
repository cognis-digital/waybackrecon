"""Offline smoke tests for WAYBACKRECON. No network access."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from waybackrecon import TOOL_NAME, TOOL_VERSION, analyze, parse_cdx_lines, severity_rank  # noqa: E402
from waybackrecon.cli import main, _render_html  # noqa: E402

SAMPLE = [
    "com,example)/ 20180101120000 https://example.com/ text/html 200 X 10",
    "https://example.com/login?next=/account",
    "https://example.com/.env",
    "https://example.com/connect?api_key=sk_live_secret123",
    "https://example.com/go?redirect=https://evil.test",
    "https://example.com/download?file=../../etc/passwd",
    "https://example.com/.htpasswd",
    "# a comment line",
    "",
]


class TestCore(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "waybackrecon")
        self.assertTrue(TOOL_VERSION)

    def test_severity_rank(self):
        self.assertLess(severity_rank("info"), severity_rank("critical"))
        self.assertEqual(severity_rank("nonexistent"), 0)

    def test_parse_mixed_formats(self):
        recs = list(parse_cdx_lines(SAMPLE))
        urls = [r.url for r in recs]
        self.assertIn("https://example.com/", urls)
        self.assertIn("https://example.com/.env", urls)
        # comments and blanks dropped
        self.assertEqual(len(recs), 7)
        # CDX timestamp parsed
        self.assertEqual(recs[0].timestamp, "20180101120000")
        self.assertEqual(recs[0].status, "200")

    def test_analyze_finds_critical(self):
        result = analyze(SAMPLE)
        cats = {f.category for f in result.findings}
        self.assertIn("secret-in-url", cats)
        self.assertIn("config-file", cats)   # .env
        self.assertIn("secret-file", cats)   # .htpasswd
        self.assertIn("param:open-redirect", cats)
        self.assertIn("param:lfi-path", cats)
        # critical findings present
        self.assertTrue(any(f.severity == "critical" for f in result.findings))

    def test_dedup_and_counts(self):
        dupd = SAMPLE + ["https://example.com/.env"]
        result = analyze(dupd)
        self.assertEqual(result.total_urls, 8)
        self.assertLess(result.unique_urls, result.total_urls)
        # .env should only produce one config-file finding despite duplicate
        env_findings = [f for f in result.findings if f.category == "config-file"]
        self.assertEqual(len(env_findings), 1)

    def test_min_severity_filter(self):
        all_f = analyze(SAMPLE)
        high_only = analyze(SAMPLE, min_severity="high")
        self.assertLess(len(high_only.findings), len(all_f.findings))
        self.assertTrue(all(severity_rank(f.severity) >= severity_rank("high")
                            for f in high_only.findings))

    def test_json_serializable(self):
        result = analyze(SAMPLE)
        blob = json.dumps(result.as_dict())
        self.assertIn("findings", blob)
        self.assertIn("summary", blob)

    def test_html_self_contained(self):
        result = analyze(SAMPLE)
        out = _render_html(result)
        self.assertIn("<!doctype html>", out)
        self.assertIn("<style>", out)          # inline CSS
        self.assertIn("WAYBACKRECON", out)
        # no external resource references
        self.assertNotIn("http://", out.split("<body>")[0])


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(os.path.dirname(__file__), "_tmp_input.txt")
        with open(self.tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(SAMPLE))

    def tearDown(self):
        for p in (self.tmp, self.tmp + ".html"):
            if os.path.exists(p):
                os.remove(p)

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_no_command_returns_2(self):
        self.assertEqual(main([]), 2)

    def test_scan_table_exit_code(self):
        # medium+ findings -> exit 1
        rc = main(["scan", self.tmp, "--format", "table"])
        self.assertEqual(rc, 1)

    def test_scan_json(self):
        rc = main(["scan", self.tmp, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_scan_html_output_file(self):
        out = self.tmp + ".html"
        rc = main(["scan", self.tmp, "--format", "html", "-o", out])
        self.assertEqual(rc, 1)
        self.assertTrue(os.path.exists(out))
        with open(out, encoding="utf-8") as fh:
            self.assertIn("<!doctype html>", fh.read())

    def test_missing_file_returns_2(self):
        rc = main(["scan", "/no/such/file/here.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
