import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from permit_safety_checker import UINT256_MAX, inspect, integer

TOKEN = "0x1111111111111111111111111111111111111111"
OWNER = "0x2222222222222222222222222222222222222222"
SPENDER = "0x3333333333333333333333333333333333333333"


def permit(value="42", deadline="2000000000"):
    return {
        "standard": "EIP-2612",
        "domain": {"verifyingContract": TOKEN, "chainId": 1},
        "message": {"owner": OWNER, "spender": SPENDER, "value": value, "nonce": 0, "deadline": deadline},
    }


class PermitSafetyTests(unittest.TestCase):
    def test_reports_raw_allowance_and_future_deadline(self):
        now = int(datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp())
        report = inspect(permit(), now)
        self.assertIn("Allowance: 42 raw token units", report)
        self.assertIn("not expired", report)

    def test_handles_uint256_deadline_beyond_datetime_range(self):
        report = inspect(permit(deadline=str(UINT256_MAX)), 1)
        self.assertIn(f"Unix timestamp {UINT256_MAX} (outside supported datetime range)", report)
        self.assertIn("not expired", report)

    def test_flags_maximum_allowance(self):
        self.assertIn("maximum uint256 allowance", inspect(permit(str(UINT256_MAX)), 1))

    def test_flags_zero_address_fields(self):
        data = permit()
        data["message"]["spender"] = "0x" + "0" * 40
        self.assertIn("zero address in spender", inspect(data, 1))

    def test_rejects_chain_id_above_uint256(self):
        with self.assertRaisesRegex(ValueError, "fit in uint256"):
            integer(str(UINT256_MAX + 1), "chainId")

    def test_cli_rejects_duplicate_json_keys(self):
        project = Path(__file__).parent
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "duplicate.json"
            path.write_text('{"standard":"EIP-2612","standard":"other"}', encoding="utf-8")
            result = subprocess.run([sys.executable, str(project / "permit_safety_checker.py"), str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate JSON key", result.stderr)


if __name__ == "__main__":
    unittest.main()
