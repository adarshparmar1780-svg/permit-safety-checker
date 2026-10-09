#!/usr/bin/env python3
"""Explain the risk-relevant fields in decoded EIP-2612 permit data."""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
UINT256_MAX = 2**256 - 1


def address(value, label):
    if not isinstance(value, str) or not ADDRESS.fullmatch(value):
        raise ValueError(f"{label} must be a 0x-prefixed 20-byte address")
    return value


def integer(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{label} must be an integer or decimal string")
    try:
        result = int(value, 10) if isinstance(value, str) else value
    except ValueError as exc:
        raise ValueError(f"{label} must be a decimal integer") from exc
    if result < 0 or result > UINT256_MAX:
        raise ValueError(f"{label} must fit in uint256")
    return result


def inspect(data, now):
    if not isinstance(data, dict) or data.get("standard") != "EIP-2612":
        raise ValueError('standard must be "EIP-2612"')
    domain = data.get("domain")
    message = data.get("message")
    if not isinstance(domain, dict) or not isinstance(message, dict):
        raise ValueError("domain and message must be JSON objects")

    token = address(domain.get("verifyingContract"), "domain.verifyingContract")
    owner = address(message.get("owner"), "message.owner")
    spender = address(message.get("spender"), "message.spender")
    chain_id = integer(domain.get("chainId"), "domain.chainId")
    value = integer(message.get("value"), "message.value")
    nonce = integer(message.get("nonce"), "message.nonce")
    deadline = integer(message.get("deadline"), "message.deadline")

    expiry = datetime.fromtimestamp(deadline, timezone.utc).isoformat() if deadline else "Unix timestamp 0"
    lines = [
        "EIP-2612 permit review (decoded fields only)",
        f"Token contract: {token}",
        f"Chain ID: {chain_id}",
        f"Owner whose tokens are affected: {owner}",
        f"Spender receiving allowance: {spender}",
        f"Allowance: {value} raw token units",
        f"Nonce: {nonce}",
        f"Deadline: {expiry}",
    ]
    if value == UINT256_MAX:
        lines.append("Risk: maximum uint256 allowance; the spender may use the full token balance until revoked or otherwise changed.")
    if deadline <= now:
        lines.append("Status: expired at the supplied current time (or Unix timestamp 0).")
    else:
        remaining = deadline - now
        lines.append(f"Status: not expired at the supplied current time; about {remaining} seconds remain.")
    lines.extend([
        "Check that you trust both the token contract and spender address before signing.",
        "This tool does not verify a signature, token decimals, contract code, or whether a transaction was submitted.",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Explain decoded EIP-2612 permit fields; never signs or submits transactions.")
    parser.add_argument("json_file", type=Path, help="path to a JSON file containing domain and message fields")
    args = parser.parse_args()
    try:
        data = json.loads(args.json_file.read_text(encoding="utf-8"))
        print(inspect(data, int(datetime.now(timezone.utc).timestamp())))
    except (OSError, json.JSONDecodeError, ValueError, OverflowError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

