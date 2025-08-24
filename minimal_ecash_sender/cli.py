from __future__ import annotations
import argparse, getpass
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from .core import (
    ATOMS_PER_XEC, DEFAULT_FEE_PER_BYTE, DEFAULT_SERVERS,
    sha256d, hash160, addr_from_h160, p2pkh_script, electrum_scripthash,
    derive_priv_pub, h160_from_addr, connect_any, build_and_sign,
)

def prompt_if_missing(args):
    if not args.mnemonic:
        try:
            m = getpass.getpass("Enter BIP39 mnemonic (will be hidden): ").strip()
        except Exception:
            m = input("Enter BIP39 mnemonic: ").strip()
        args.mnemonic = m
    if not args.to:
        args.to = input("Send to (ecash:...): ").strip()
    if args.amount_xec is None and args.amount_atoms is None:
        while True:
            a = input("Amount (in XEC, e.g. 1.23): ").strip()
            try:
                dec = Decimal(a)
                if dec <= 0: raise InvalidOperation()
                args.amount_atoms = int((dec.quantize(Decimal("0.00"), rounding=ROUND_DOWN) * Decimal(ATOMS_PER_XEC)))
                break
            except Exception:
                print("Invalid amount. Try again.")

def decide_ssl_default(args) -> bool:
    if args.server and len(args.server) > 0:
        return bool(args.ssl)
    else:
        return True  # defaults use TLS

def format_atoms(a: int) -> str:
    return f"{Decimal(a) / Decimal(ATOMS_PER_XEC)} XEC ({a} atoms)"

def main():
    ap = argparse.ArgumentParser("eCash (XEC) client: derive from mnemonic, fetch UTXOs via Electrum, build/sign/broadcast P2PKH")
    # Network / TLS
    ap.add_argument("--server", action="append", help="host:port (repeatable). If omitted, uses defaults.")
    ap.add_argument("--ssl", action="store_true", help="Use TLS for servers you pass (defaults use TLS automatically).")
    ap.add_argument("--insecure", action="store_true", help="TLS without certificate verification (testing only)")
    ap.add_argument("--ca", help="Path to CA or server certificate PEM to trust (e.g. fullchain.pem)")
    ap.add_argument("--fingerprint", help="SHA256 fingerprint of server cert (hex; colons optional) to pin")
    ap.add_argument("--timeout", type=int, default=25, help="Network timeout seconds (default 25)")

    # Wallet & spend
    ap.add_argument("--mnemonic", help="BIP39 12/24-word (if omitted, will prompt)")
    ap.add_argument("--to", help="Destination ecash:... (if omitted, will prompt)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--amount-xec", type=Decimal, help="Amount to send in XEC (1 XEC = 100 atoms). If omitted, will prompt.")
    g.add_argument("--amount-atoms", type=int, help="Amount to send in atoms")
    ap.add_argument("--path", default="m/44'/1899'/0'/0/0", help="Derivation path (use 899 if your seed used SLIP-44 899)")
    ap.add_argument("--fee-per-byte", type=int, default=DEFAULT_FEE_PER_BYTE, help="Fee rate atoms/byte (default 1)")
    args = ap.parse_args()

    # Interactive prompts if needed
    prompt_if_missing(args)

    # Amount normalization
    if args.amount_atoms is None and args.amount_xec is not None:
        try:
            args.amount_atoms = int((args.amount_xec.quantize(Decimal("0.00"), rounding=ROUND_DOWN) * Decimal(ATOMS_PER_XEC)))
        except Exception:
            raise SystemExit("invalid --amount-xec")
    if args.amount_atoms is None or args.amount_atoms <= 0:
        raise SystemExit("amount must be positive")

    # Derive keys & our address
    try:
        priv, pub = derive_priv_pub(args.mnemonic.strip(), args.path)
    except Exception as e:
        raise SystemExit(f"mnemonic/derivation error: {e}")

    my_h160 = hash160(pub)
    from_addr = addr_from_h160(my_h160)
    print(f"[wallet] from/change: {from_addr}")

    # Destination
    try:
        dest_h160 = h160_from_addr(args.to)
    except Exception:
        raise SystemExit("destination must be a valid eCash (ecash:...) P2PKH address")

    # Server list & TLS decision
    servers = args.server if (args.server and len(args.server) > 0) else DEFAULT_SERVERS
    use_ssl = decide_ssl_default(args)

    # Connect (failover; auto-trust for default hosts)
    cli, chosen = connect_any(servers, use_ssl, args.timeout, args.insecure, args.ca, args.fingerprint)

    # Fetch UTXOs & sign
    spk = p2pkh_script(my_h160)
    sh = electrum_scripthash(spk)
    try:
        utxos = cli.request("blockchain.scripthash.listunspent", [sh])
    except Exception as e:
        cli.close(); raise SystemExit(f"listunspent failed: {e}")
    if not utxos:
        cli.close(); raise SystemExit("no UTXOs for the derived address")

    try:
        raw_hex, txid_local, fee_atoms, change_atoms, size_bytes = build_and_sign(
            priv, pub, utxos, dest_h160, int(args.amount_atoms), args.fee_per_byte, my_h160
        )
    except Exception as e:
        cli.close(); raise SystemExit(f"build/sign failed: {e}")

    print(f"[tx] size: {size_bytes} bytes, fee: {format_atoms(fee_atoms)}, change: {format_atoms(change_atoms)}")
    print(f"[tx] txid (local): {txid_local}")
    print(f"[tx] raw: {raw_hex}")

    ans = input("Broadcast this transaction? [y/N]: ").strip().lower()
    if ans not in ("y", "yes"):
        cli.close(); raise SystemExit("aborted by user")

    try:
        txid_net = cli.request("blockchain.transaction.broadcast", [raw_hex])
    except Exception as e:
        cli.close(); raise SystemExit(f"broadcast failed: {e}")
    finally:
        cli.close()

    print(f"[broadcast] accepted by {chosen}: {txid_net}")

if __name__ == "__main__":
    main()