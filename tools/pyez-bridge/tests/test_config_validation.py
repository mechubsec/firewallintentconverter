"""Unit tests for configuration validation before PyEZ load."""

import sys
import unittest
from pathlib import Path


BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

from config_validation import (  # noqa: E402
    ConfigurationValidationError,
    validate_config_payload,
)


class ConfigValidationTests(unittest.TestCase):
    def test_accepts_supported_set_and_xml(self):
        set_text = (
            "# generated output\n"
            "set system host-name edge-1\n"
            "set system login message \"Ops; $(review) team\"\n"
            "deactivate security policies from-zone trust to-zone untrust policy old\n"
        )
        self.assertEqual(
            validate_config_payload(set_text, "set"),
            "set system host-name edge-1\n"
            "set system login message \"Ops; $(review) team\"\n"
            "deactivate security policies from-zone trust to-zone untrust policy old",
        )

        xml = (
            "<configuration><logical-systems><name>tenant-a</name>"
            "<system><host-name>edge-1</host-name></system>"
            "</logical-systems></configuration>"
        )
        self.assertEqual(validate_config_payload(xml, "xml"), xml)

    def test_rejects_set_injection_and_forbidden_hierarchies(self):
        payloads = (
            "set system host-name edge-1\rset system services ssh",
            "set system host-name edge\u2028set system services ssh",
            "set system host-name \"unterminated",
            "set system host-name edge; set system services telnet",
            "set system host-name $(request system reboot)",
            "set system host-name `request-system-reboot`",
            "delete security policies",
            "set groups attacker system services ssh",
            "set system root-authentication plain-text-password-value secret",
            "set system services telnet",
            "set logical-systems tenant-a system services rlogin",
            "set system scripts commit file attacker.slax",
            "set event-options policy persist events UI_COMMIT",
            # Quoting a keyword must not hide it from the hierarchy checks.
            'set system "root-authentication" encrypted-password "$6$x"',
            'set system root-"authentication" plain-text-password-value x',
            'set system services "telnet"',
            'set system "scripts" language python',
            'set logical-systems tenant-a "system" services "rlogin"',
        )
        for text in payloads:
            with self.subTest(text=text):
                with self.assertRaises(ConfigurationValidationError):
                    validate_config_payload(text, "set")

    def test_set_error_reports_line_without_reflecting_command(self):
        rejected = "set system services telnet"
        try:
            validate_config_payload(
                "set system host-name edge-1\n" + rejected,
                "set",
            )
        except ConfigurationValidationError as error:
            self.assertEqual(error.line, 2)
            self.assertNotIn(rejected, str(error))
        else:
            self.fail("expected validation to reject the second line")

    def test_rejects_xml_entities_outside_content_and_dangerous_paths(self):
        payloads = (
            '<!DOCTYPE configuration [<!ENTITY x SYSTEM "file:///etc/passwd">]><configuration>&x;</configuration>',
            "<configuration/><configuration/>",
            "<!-- outside --><configuration/>",
            "<configuration><groups><name>x</name></groups></configuration>",
            "<configuration><system><services><telnet/></services></system></configuration>",
            "<configuration><logical-systems><name>a</name><system><services><rlogin/></services></system></logical-systems></configuration>",
            "<configuration><system><scripts><commit><file>x</file></commit></scripts></system></configuration>",
            "<configuration><![CDATA[<system/>]]></configuration>",
            "<?evil data?><configuration/>",
        )
        for text in payloads:
            with self.subTest(text=text):
                with self.assertRaises(ConfigurationValidationError):
                    validate_config_payload(text, "xml")

    def test_disables_text_load_and_unknown_formats(self):
        for fmt in ("text", "json", ""):
            with self.subTest(fmt=fmt):
                with self.assertRaises(ConfigurationValidationError):
                    validate_config_payload(
                        "system { host-name edge-1; }",
                        fmt,
                    )


if __name__ == "__main__":
    unittest.main()
