# minimal-ecash-sender

Minimal **eCash (XEC)** Electrum/Fulcrum client.

- Builds, signs, and broadcasts **P2PKH** transactions (SIGHASH_ALL|FORKID)
- Derives from a **BIP39 mnemonic** (`m/44'/1899'/0'/0/0` default)
- Defaults to TLS servers (auto-trusted):  
  `electrum.bitcoinabc.org`, `fulcrum.pepipierre.fr`, `electrum.bytesofman.com`

## Install

```
pip install minimal-ecash-sender
```

## CLI
