# minimal-ecash-sender

Minimal **eCash (XEC)** Electrum ABC/Fulcrum client.

- Builds, signs, and broadcasts **P2PKH** transactions (`SIGHASH_ALL|FORKID`)
- Derives from a **BIP39 mnemonic** (default path: `m/44'/1899'/0'/0/0`)
- Uses TLS by default with these auto-trusted servers (port **50002**):
  - `electrum.bitcoinabc.org`
  - `fulcrum.pepipierre.fr`
  - `electrum.bytesofman.com`

---

## Install

```bash
pip install minimal-ecash-sender
```

## Library Usage

```python
from minimal_ecash_sender.core import send_xec

txid, raw_hex = send_xec(
    mnemonic="twelve words ...",
    to_addr="ecash:qq5teh...",
    amount_atoms=1234,              # 12.34 XEC = 1234 atoms (satoshi)
    servers=None,                   # use defaults
    fee_per_byte=1,
    derivation_path="m/44'/1899'/0'/0/0", #Cashtab wallet's derivation path
    timeout=25,
)
print(txid, raw_hex)
```
### Flags

- `--server host:port`  Repeatable; if omitted, defaults are used (TLS 50002)
- `--ssl`  Only needed when you pass custom servers and want TLS
- `--insecure`  Disable TLS verification (testing only)
- `--ca PATH`  Custom CA bundle (PEM)
- `--fingerprint HEX`  Pin server by SHA-256 fingerprint
- `--timeout INT`  Request timeout (default: 25)
- `--mnemonic "..."`  BIP39 mnemonic
- `--to ecash:...`  Destination eCash **P2PKH** address
- `--amount-xec DECIMAL`  Send in XEC (note: **1 XEC = 100 atoms**)
- `--amount-atoms INT`  Send in atoms
- `--path "m/44'/1899'/0'/0/0"`  Derivation path
- `--fee-per-byte INT`  Atoms/byte (default: 1)
---

## Notes

- Only **P2PKH** is supported.
- Default fee rate is **1 atom/byte**; adjust with `--fee-per-byte` if needed.

<<<<<<< HEAD
See `LICENSE`.
=======
See `LICENSE`.

>>>>>>> 1d1f3f7eecf88bc9effba6bfee7ded3956d96d20
