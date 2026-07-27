from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "src" / "seer_client.py"
SPEC = importlib.util.spec_from_file_location("seer_client", MODULE_PATH)
assert SPEC and SPEC.loader
seer_client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seer_client)


class SeerClientTests(unittest.TestCase):
    def test_release_config_requires_exact_secure_enrollment_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.conf"
            path.write_text(
                "SEER_ENROLLMENT_URL=https://vpn.example.com:8443/api/vpn/enroll\n"
                f"SEER_CERTIFICATE_SHA256={'a' * 64}\n",
                encoding="utf-8",
            )
            self.assertEqual(
                seer_client.read_release_config(path),
                {
                    "endpoint": "https://vpn.example.com:8443/api/vpn/enroll",
                    "fingerprint": "a" * 64,
                },
            )

            for endpoint in (
                "http://vpn.example.com/api/vpn/enroll",
                "https://user:pass@vpn.example.com/api/vpn/enroll",
                "https://vpn.example.com/api/vpn/enroll?next=bad",
                "https://vpn.example.com/not-enrollment",
            ):
                path.write_text(
                    f"SEER_ENROLLMENT_URL={endpoint}\n"
                    f"SEER_CERTIFICATE_SHA256={'a' * 64}\n",
                    encoding="utf-8",
                )
                with self.assertRaises(seer_client.SeerClientError):
                    seer_client.read_release_config(path)

    def test_enrollment_reports_linux_without_os_version(self) -> None:
        invitation = "A" * 43
        with (
            patch.object(seer_client, "installation_id", return_value="test-device-installation"),
            patch.object(
                seer_client,
                "device_details",
                return_value={
                    "manufacturer": "Example",
                    "model": "File Server",
                    "os": "Linux",
                    "appVersion": "1.0.0",
                },
            ),
        ):
            payload = json.loads(seer_client.enrollment_payload(invitation))
        self.assertEqual(payload["device"]["os"], "Linux")
        self.assertNotIn("Ubuntu", repr(payload))
        self.assertNotIn("22.04", repr(payload))

    def test_presence_url_accepts_only_expected_private_service(self) -> None:
        good = (
            "# SEER-PRESENCE-URL: "
            "http%3A%2F%2F10.8.0.1%3A3001%2Fapi%2Fvpn%2Fclient-presence\n"
        )
        self.assertEqual(
            seer_client.presence_url(good),
            "http://10.8.0.1:3001/api/vpn/client-presence",
        )
        self.assertEqual(
            seer_client.presence_url(
                "# SEER-PRESENCE-URL: http%3A%2F%2Fevil.example%2Fcollect\n"
            ),
            "http://10.8.0.1:3000/api/vpn/client-presence",
        )

    def test_network_configuration_is_rejected_when_incomplete(self) -> None:
        with self.assertRaises(seer_client.SeerClientError):
            seer_client.validate_network_config("[Interface]\nAddress = 10.8.0.9/32\n")


if __name__ == "__main__":
    unittest.main()

