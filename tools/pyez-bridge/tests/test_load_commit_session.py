"""Tests for the all-or-nothing load / same-session commit-check / commit flow.

A failed load must never fall back to committing partial config, and a
commit must never run against a fresh, unchecked session — see MEC-21.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

import app as app_module  # noqa: E402
from app import create_app  # noqa: E402
from jnpr.junos.exception import CommitError, ConfigLoadError  # noqa: E402


TOKEN = "load-commit-session-bridge-token-32ch"
ALLOWED_ORIGIN = "http://localhost:5173"


def write_inventory(path, text):
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)


class LoadCommitSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.devices_file = Path(self.temp_dir.name) / "devices.yaml"
        write_inventory(
            self.devices_file,
            "devices:\n"
            "  - name: edge\n"
            "    host: 192.0.2.10\n"
            "    port: 830\n"
            "    username: netops\n"
            "    auth_method: agent\n",
        )
        self.devices_patch = patch.object(
            app_module, "DEVICES_FILE", self.devices_file
        )
        self.devices_patch.start()
        self.addCleanup(self.devices_patch.stop)
        # Load sessions are module-global; never let one test's session
        # bleed into the next.
        self.addCleanup(app_module._load_sessions.clear)
        self.app = create_app(
            {
                "TESTING": True,
                "BRIDGE_TOKEN": TOKEN,
                "BRIDGE_ALLOWED_ORIGINS": [ALLOWED_ORIGIN],
            }
        )
        self.client = self.app.test_client()
        self.auth = {"Authorization": f"Bearer {TOKEN}"}

    def _load(self, dev, config, config_text="set system host-name edge"):
        with patch.object(app_module, "_connect", return_value=dev):
            with patch.object(app_module, "Config", return_value=config):
                response = self.client.post(
                    "/devices/edge/load",
                    json={"format": "set", "config": config_text},
                    headers=self.auth,
                )
        self.assertTrue(response.get_json()["ok"], response.get_json())
        return response

    def test_partial_load_failure_is_fail_closed(self):
        dev = Mock()
        config = Mock()
        config.load.side_effect = ConfigLoadError(
            None, errs=[{"message": "bad syntax", "severity": "error"}]
        )
        with patch.object(app_module, "_connect", return_value=dev):
            with patch.object(app_module, "Config", return_value=config):
                response = self.client.post(
                    "/devices/edge/load",
                    json={
                        "format": "set",
                        "config": (
                            "set system host-name edge\n"
                            "set interfaces ge-0/0/0 description example"
                        ),
                    },
                    headers=self.auth,
                )
        body = response.get_json()
        self.assertEqual(response.status_code, 502)
        self.assertFalse(body["ok"])
        self.assertNotIn("loaded", body)
        self.assertNotIn("skipped", body)
        self.assertNotIn("warnings", body)
        # The whole config is tried once — no per-line retry loop.
        config.load.assert_called_once()
        config.rpc.close_configuration.assert_called_once_with()
        dev.close.assert_called_once_with()
        self.assertIsNone(app_module._get_session("edge"))

        # Nothing was stored, so a follow-up commit-check/commit must fail
        # closed without touching the device.
        with patch.object(app_module, "_connect") as connect_mock:
            cc_response = self.client.post(
                "/devices/edge/commit-check", headers=self.auth
            )
            commit_response = self.client.post(
                "/devices/edge/commit", headers=self.auth
            )
        self.assertEqual(cc_response.status_code, 409)
        self.assertEqual(commit_response.status_code, 409)
        connect_mock.assert_not_called()

    def test_successful_load_stores_session(self):
        dev = Mock()
        config = Mock()
        with patch.object(app_module, "_connect", return_value=dev) as connect_mock:
            with patch.object(app_module, "Config", return_value=config):
                response = self.client.post(
                    "/devices/edge/load",
                    json={"format": "set", "config": "set system host-name edge"},
                    headers=self.auth,
                )
        self.assertTrue(response.get_json()["ok"])
        connect_mock.assert_called_once()
        config.rpc.open_configuration.assert_called_once_with(private=True)
        dev.close.assert_not_called()

        session = app_module._get_session("edge")
        self.assertIsNotNone(session)
        self.assertIs(session.dev, dev)
        self.assertIs(session.cu, config)
        self.assertFalse(session.checked)

    def test_commit_check_failure_blocks_commit(self):
        dev = Mock()
        config = Mock()
        self._load(dev, config)
        config.commit_check.side_effect = CommitError(
            None, errs=[{"message": "check failed", "severity": "error"}]
        )

        response = self.client.post("/devices/edge/commit-check", headers=self.auth)
        self.assertEqual(response.status_code, 502)
        self.assertIsNone(app_module._get_session("edge"))
        dev.close.assert_called_once_with()

        with patch.object(app_module, "_connect") as connect_mock:
            commit_response = self.client.post(
                "/devices/edge/commit", headers=self.auth
            )
        self.assertEqual(commit_response.status_code, 409)
        config.commit.assert_not_called()
        connect_mock.assert_not_called()

    def test_commit_without_prior_commit_check_is_refused(self):
        dev = Mock()
        config = Mock()
        self._load(dev, config)

        with patch.object(app_module, "_connect") as connect_mock:
            response = self.client.post(
                "/devices/edge/commit", json={"comment": "x"}, headers=self.auth
            )
        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.get_json()["ok"])
        config.commit.assert_not_called()
        connect_mock.assert_not_called()
        # The session survives — it just isn't checked yet.
        self.assertIsNotNone(app_module._get_session("edge"))

    def test_commit_reuses_the_load_session_connection(self):
        dev = Mock()
        config = Mock()
        self._load(dev, config)
        self.client.post("/devices/edge/commit-check", headers=self.auth)

        with patch.object(app_module, "_connect") as connect_mock:
            with patch.object(app_module, "Config") as config_cls:
                response = self.client.post(
                    "/devices/edge/commit",
                    json={"comment": "ok"},
                    headers=self.auth,
                )
        self.assertTrue(response.get_json()["ok"])
        connect_mock.assert_not_called()
        config_cls.assert_not_called()
        config.commit.assert_called_once_with(comment="ok")

    def test_diff_and_commit_check_use_the_load_session(self):
        dev = Mock()
        config = Mock()
        config.diff.return_value = "diff-output"
        self._load(dev, config)

        with patch.object(app_module, "_connect") as connect_mock:
            diff_response = self.client.get("/devices/edge/diff", headers=self.auth)
            cc_response = self.client.post(
                "/devices/edge/commit-check", headers=self.auth
            )
        self.assertEqual(diff_response.get_json()["diff"], "diff-output")
        self.assertTrue(cc_response.get_json()["ok"])
        connect_mock.assert_not_called()
        config.diff.assert_called_once_with()
        config.commit_check.assert_called_once_with()

    def test_successful_commit_closes_the_session(self):
        dev = Mock()
        config = Mock()
        self._load(dev, config)
        self.client.post("/devices/edge/commit-check", headers=self.auth)

        response = self.client.post(
            "/devices/edge/commit", json={"comment": "done"}, headers=self.auth
        )
        self.assertTrue(response.get_json()["ok"])
        self.assertIsNone(app_module._get_session("edge"))
        dev.close.assert_called_once_with()

    def test_confirm_active_reflects_the_timer_actually_set(self):
        for minutes, expected in ((5, True), ("5", True), (0, False), ("0", False), (-1, False)):
            with self.subTest(minutes=minutes):
                dev = Mock()
                config = Mock()
                self._load(dev, config)
                self.client.post("/devices/edge/commit-check", headers=self.auth)

                response = self.client.post(
                    "/devices/edge/commit",
                    json={"confirm_minutes": minutes},
                    headers=self.auth,
                )
                self.assertEqual(response.get_json()["confirm_active"], expected)
                if expected:
                    config.commit.assert_called_once_with(confirm=5)
                else:
                    config.commit.assert_called_once_with()

    def test_invalid_confirm_minutes_is_rejected_before_commit(self):
        dev = Mock()
        config = Mock()
        self._load(dev, config)
        self.client.post("/devices/edge/commit-check", headers=self.auth)

        response = self.client.post(
            "/devices/edge/commit",
            json={"confirm_minutes": "soon"},
            headers=self.auth,
        )
        self.assertEqual(response.status_code, 400)
        config.commit.assert_not_called()
        self.assertIsNotNone(app_module._get_session("edge"))

    def test_failed_commit_discards_the_session(self):
        dev = Mock()
        config = Mock()
        self._load(dev, config)
        self.client.post("/devices/edge/commit-check", headers=self.auth)
        config.commit.side_effect = CommitError(
            None, errs=[{"message": "commit failed", "severity": "error"}]
        )

        response = self.client.post(
            "/devices/edge/commit", json={"comment": "x"}, headers=self.auth
        )
        self.assertEqual(response.status_code, 502)
        self.assertIsNone(app_module._get_session("edge"))
        dev.close.assert_called_once_with()

        # A retry must not silently reuse the stale, failed session.
        with patch.object(app_module, "_connect") as connect_mock:
            retry_response = self.client.post(
                "/devices/edge/commit", json={"comment": "x"}, headers=self.auth
            )
        self.assertEqual(retry_response.status_code, 409)
        connect_mock.assert_not_called()

    def test_confirm_unsupported_on_private_returns_fixed_code(self):
        dev = Mock()
        config = Mock()
        self._load(dev, config)
        self.client.post("/devices/edge/commit-check", headers=self.auth)
        config.commit.side_effect = CommitError(
            None,
            errs=[
                {
                    "message": "commit confirmed not supported for private configuration",
                    "severity": "error",
                }
            ],
        )

        response = self.client.post(
            "/devices/edge/commit",
            json={"comment": "x", "confirm_minutes": 1},
            headers=self.auth,
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 409)
        self.assertFalse(body["ok"])
        self.assertEqual(body["code"], "CONFIRM_UNSUPPORTED_ON_PRIVATE")
        self.assertNotIn("private configuration", body["error"])
        self.assertIsNone(app_module._get_session("edge"))
        dev.close.assert_called_once_with()

    def test_similarly_worded_commit_error_is_not_misclassified(self):
        """Only the exact device string maps to the fixed code — see MEC-172."""
        dev = Mock()
        config = Mock()
        self._load(dev, config)
        self.client.post("/devices/edge/commit-check", headers=self.auth)
        config.commit.side_effect = CommitError(
            None,
            errs=[
                {
                    "message": "commit confirmed not supported here",
                    "severity": "error",
                }
            ],
        )

        response = self.client.post(
            "/devices/edge/commit",
            json={"comment": "x", "confirm_minutes": 1},
            headers=self.auth,
        )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["code"], "DEVICE_OPERATION_FAILED")


if __name__ == "__main__":
    unittest.main()
