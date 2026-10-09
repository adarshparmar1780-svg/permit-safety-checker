# Permit Safety Checker

A small, offline Python tool that explains the key fields in **decoded EIP-2612 permit data**: the token contract, owner, spender, raw allowance, nonce, and deadline. It calls out the exact maximum `uint256` allowance.

## Run

Requires Python 3.10 or newer. No packages or network access are needed.

```powershell
python .\permit_safety_checker.py .\example-permit.json
```

Use only with decoded EIP-2612 JSON shaped like the included example. The allowance is shown in raw token units because token decimals are not checked.

## Limits

This is an educational explanation tool, not a wallet, signature verifier, contract scanner, or security audit. It does not determine whether a signature is valid, whether the token or spender is trustworthy, or whether a permit was submitted. Never paste a seed phrase or private key into this tool.

AI-assisted initial draft. Review and understand the code before presenting it as your work.
