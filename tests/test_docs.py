from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DocumentationIntegrityTests(unittest.TestCase):
    def test_required_documents_exist(self):
        required = [
            "README.md",
            "docs/scope-and-limits.md",
            "docs/wire-size-notes.md",
            "docs/handshake-and-operational-notes.md",
            "examples/sample-cost-row.md",
            "requirements.txt",
        ]
        for relative in required:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), relative)

    def test_internal_markdown_links_resolve(self):
        markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")),
                          *sorted((ROOT / "examples").glob("*.md"))]
        link_pattern = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")
        for source in markdown_files:
            content = source.read_text(encoding="utf-8")
            for target in link_pattern.findall(content):
                target = target.strip().split()[0].strip("<>")
                is_external = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target)
                if not target or is_external or target.startswith("#"):
                    continue
                path = target.split("#", 1)[0].split("?", 1)[0]
                if path:
                    with self.subTest(source=source.relative_to(ROOT), target=target):
                        self.assertTrue((source.parent / path).resolve().is_file(),
                                        f"Broken internal link: {target}")

    def test_documented_key_share_arithmetic(self):
        client_hybrid, server_hybrid = 1216, 1120
        client_x25519 = server_x25519 = 32
        client_p256 = server_p256 = 65
        hybrid_total = client_hybrid + server_hybrid
        self.assertEqual(hybrid_total, 2336)
        self.assertEqual(hybrid_total - (client_x25519 + server_x25519), 2272)
        self.assertEqual(hybrid_total - (client_p256 + server_p256), 2206)

    def test_wire_notes_state_measurement_boundary(self):
        text = (ROOT / "docs/wire-size-notes.md").read_text(encoding="utf-8")
        for phrase in ("Specification-derived", "or a packet-capture result",
                       "not a like-for-like P-256 hybrid group comparison",
                       "TLS record bytes", "TCP/IP bytes"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_sample_row_is_explicitly_not_measured(self):
        text = (ROOT / "examples/sample-cost-row.md").read_text(encoding="utf-8")
        self.assertIn("not an observation", text)
        self.assertIn("Specification-derived arithmetic; not measured", text)

    def test_repository_is_a_python_package(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Python package", readme)
        self.assertTrue((ROOT / "pyproject.toml").is_file())
        self.assertTrue((ROOT / "src/pqtls/cli.py").is_file())


if __name__ == "__main__":
    unittest.main()
