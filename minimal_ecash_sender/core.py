from __future__ import annotations
import json, socket, ssl, hashlib, struct, time
from typing import List, Optional, Tuple
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize
from bip_utils import Bip39MnemonicValidator, Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip39Languages
from ecashaddress import convert as ecash_convert
from decimal import Decimal, ROUND_DOWN, InvalidOperation
import base58

# ===== Constants & defaults =====
ATOMS_PER_XEC = 100
SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40
SIGHASH_ALL_FORKID = SIGHASH_ALL | SIGHASH_FORKID
DUST = 100
DEFAULT_FEE_PER_BYTE = 1

DEFAULT_SERVERS = [
    "electrum.bitcoinabc.org:50002",
    "fulcrum.pepipierre.fr:50002",
    "electrum.bytesofman.com:50002",
]

# Always auto-trust TLS certs for these hosts
ALWAYS_TRUST_HOSTS = {
    "electrum.bitcoinabc.org",
    "fulcrum.pepipierre.fr",
    "electrum.bytesofman.com",
}

# ===== Small helpers =====
def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def sha256d(b: bytes) -> bytes: return sha256(sha256(b))
def ripemd160(b: bytes) -> bytes: h = hashlib.new("ripemd160"); h.update(b); return h.digest()
def hash160(b: bytes) -> bytes: return ripemd160(sha256(b))
def le32(n: int) -> bytes: return struct.pack("<I", n)
def le64(n: int) -> bytes: return struct.pack("<Q", n)

def varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def push(data: bytes) -> bytes:
    l = len(data)
    if l < 0x4c: return bytes([l]) + data
    if l <= 0xff: return b'\x4c' + bytes([l]) + data
    if l <= 0xffff: return b'\x4d' + struct.pack('<H', l) + data
    return b'\x4e' + struct.pack('<I', l) + data

def p2pkh_script(h160: bytes) -> bytes:
    # OP_DUP OP_HASH160 <20> <h160> OP_EQUALVERIFY OP_CHECKSIG
    return b'\x76\xa9' + bytes([20]) + h160 + b'\x88\xac'

def electrum_scripthash(script_pubkey: bytes) -> str:
    # SHA256(scriptPubKey), little-endian hex
    return hashlib.sha256(script_pubkey).digest()[::-1].hex()

# ===== Electrum client =====
class Electrum:
    def __init__(self, host: str, port: int, use_ssl=True, timeout=25,
                 insecure: bool=False, cafile: Optional[str]=None, fingerprint: Optional[str]=None):
        self.host, self.port = host, port
        self.use_ssl, self.timeout = use_ssl, timeout
        self.insecure, self.cafile = insecure, cafile
        self.fingerprint = (fingerprint or "").replace(":", "").lower() or None
        self.sock = None
        self._id = 0

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_ssl:
            if self.insecure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                ctx = ssl.create_default_context(cafile=self.cafile) if self.cafile else ssl.create_default_context()
            ssock = ctx.wrap_socket(raw, server_hostname=None if self.insecure else self.host)

            if self.fingerprint:
                der = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(der).hexdigest().lower()
                if fp != self.fingerprint:
                    ssock.close()
                    raise ssl.SSLError(f"TLS fingerprint mismatch: expected {self.fingerprint}, got {fp}")
            self.sock = ssock
        else:
            self.sock = raw

        # Negotiate protocol version
        try:
            self.request("server.version", ["xec-tool 1.0", ["1.4", "1.6"]])
        except RuntimeError as e:
            if "Unsupported protocol version" in str(e):
                self.request("server.version", ["xec-tool 1.0", "1.4"])
            else:
                raise

    def close(self):
        try:
            if self.sock: self.sock.close()
        except: pass

    def _read_line(self) -> str:
        buf = b""
        start = time.time()
        while b"\n" not in buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("Connection closed by server")
            buf += chunk
            if time.time() - start > self.timeout:
                raise TimeoutError("Timeout waiting Electrum response")
        line, _, _ = buf.partition(b"\n")
        return line.decode()

    def request(self, method: str, params: list):
        self._id += 1
        msg = json.dumps({"jsonrpc":"2.0","id":self._id,"method":method,"params":params}) + "\n"
        self.sock.sendall(msg.encode())
        resp = json.loads(self._read_line())
        if "error" in resp and resp["error"]:
            raise RuntimeError(f"{method} error: {resp['error']}")
        return resp["result"]

# ===== Keys / addresses =====
def derive_priv_pub(mnemonic: str, path: str) -> Tuple[bytes, bytes]:
    Bip39MnemonicValidator(Bip39Languages.ENGLISH).Validate(mnemonic.strip())
    seed = Bip39SeedGenerator(mnemonic).Generate()
    node = Bip32Slip10Secp256k1.FromSeed(seed).DerivePath(path)
    priv = node.PrivateKey().Raw().ToBytes()
    pub = node.PublicKey().RawCompressed().ToBytes()
    return priv, pub

def addr_from_h160(h160: bytes) -> str:
    payload = bytes([0x00]) + h160
    legacy = base58.b58encode(payload + sha256d(payload)[:4]).decode()
    return ecash_convert.Address.from_string(legacy).to_cash_address(prefix="ecash")

def h160_from_addr(addr: str) -> bytes:
    legacy = ecash_convert.Address.from_string(addr).to_legacy_address()
    raw = base58.b58decode_check(legacy)
    if raw[0] != 0x00:
        raise ValueError("Unsupported address (not mainnet P2PKH)")
    return raw[1:]

# ===== Tx build/sign =====
def serialize_input(txid_be_hex: str, vout: int, script_sig: bytes, seq=0xffffffff) -> bytes:
    txid_le = bytes.fromhex(txid_be_hex)[::-1]
    return txid_le + le32(vout) + varint(len(script_sig)) + script_sig + le32(seq)

def serialize_output(value: int, spk: bytes) -> bytes:
    return le64(value) + varint(len(spk)) + spk

def est_size(n_in: int, n_out: int) -> int:
    return 10 + 148*n_in + 34*n_out

def sighash_bch(version, txins, txouts, locktime, in_index, script_code, prev_value, sighash_type=SIGHASH_ALL_FORKID):
    hash_prevouts = sha256d(b"".join([bytes.fromhex(t['tx_hash'])[::-1] + le32(t['tx_pos']) for t in txins]))
    hash_sequence = sha256d(b"".join([le32(0xffffffff) for _ in txins]))
    hash_outputs = sha256d(b"".join([serialize_output(o['value'], o['script']) for o in txouts]))
    this_in = txins[in_index]
    preimage = (
        le32(version) +
        hash_prevouts +
        hash_sequence +
        bytes.fromhex(this_in['tx_hash'])[::-1] + le32(this_in['tx_pos']) +
        varint(len(script_code)) + script_code +
        le64(prev_value) + le32(0xffffffff) +
        hash_outputs + le32(locktime) + le32(sighash_type)
    )
    return sha256d(preimage)

def build_and_sign(priv: bytes, pub: bytes, utxos: List[dict], to_h160: bytes,
                   amount: int, fee_per_byte: int, change_h160: bytes) -> Tuple[str, str, int, int, int]:
    candidates = sorted(utxos, key=lambda u: u["value"], reverse=True)
    sel, total = [], 0
    for u in candidates:
        sel.append(u); total += u["value"]
        if total >= amount + fee_per_byte*est_size(len(sel), 2): break
    if total < amount + fee_per_byte*est_size(len(sel), 1):
        raise ValueError("insufficient funds")

    dest_spk = p2pkh_script(to_h160)
    change_spk = p2pkh_script(change_h160)
    version, locktime = 2, 0

    outs = [{"value": amount, "script": dest_spk}]
    fee_guess = fee_per_byte * est_size(len(sel), 2)
    change = total - amount - fee_guess
    if change >= DUST:
        outs.append({"value": change, "script": change_spk})

    sk = SigningKey.from_string(priv, curve=SECP256k1)
    signed_ins = []
    for idx, u in enumerate(sel):
        script_code = p2pkh_script(hash160(pub))
        digest = sighash_bch(version, sel, outs, locktime, idx, script_code, u["value"])
        sig = sk.sign_digest(digest, sigencode=sigencode_der_canonize) + bytes([SIGHASH_ALL_FORKID])
        script_sig = push(sig) + push(pub)
        signed_ins.append(serialize_input(u["tx_hash"], u["tx_pos"], script_sig))

    raw = (
        le32(version) +
        varint(len(signed_ins)) + b"".join(signed_ins) +
        varint(len(outs)) + b"".join([serialize_output(o["value"], o["script"]) for o in outs]) +
        le32(locktime)
    )
    txid = sha256d(raw)[::-1].hex()
    size = len(raw)
    total_out = sum(o["value"] for o in outs)
    fee_exact = total - total_out
    change_final = change if len(outs) == 2 else 0
    return raw.hex(), txid, fee_exact, change_final, size

# ===== Net helpers & library entrypoint =====
def connect_any(servers: List[str], use_ssl: bool, timeout: int,
                insecure: bool=False, cafile: Optional[str]=None,
                fingerprint: Optional[str]=None) -> Tuple[Electrum, str]:
    last_err = None
    for s in servers:
        try:
            host, port = s.split(":"); port = int(port)
        except:
            continue
        try:
            auto_insecure = insecure or (host in ALWAYS_TRUST_HOSTS)
            cli = Electrum(host, port, use_ssl=use_ssl, timeout=timeout,
                           insecure=auto_insecure, cafile=cafile, fingerprint=fingerprint)
            cli.connect()
            return cli, s
        except Exception as e:
            last_err = e
            if port == 50001 and use_ssl:
                try:
                    cli = Electrum(host, port, use_ssl=False, timeout=timeout,
                                   insecure=False, cafile=None, fingerprint=None)
                    cli.connect()
                    return cli, s
                except Exception as e2:
                    last_err = e2
    raise ConnectionError(f"failed to connect to any server: {last_err}")

def send_xec(
    mnemonic: str,
    to_addr: str,
    amount_atoms: int,
    servers: Optional[List[str]] = None,
    fee_per_byte: int = DEFAULT_FEE_PER_BYTE,
    derivation_path: str = "m/44'/1899'/0'/0/0",
    timeout: int = 25,
    use_ssl: Optional[bool] = None,
    insecure: bool = False,
    cafile: Optional[str] = None,
    fingerprint: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Build, sign and broadcast a P2PKH transaction on eCash.

    Returns: (txid_from_network, raw_tx_hex)
    """
    if amount_atoms <= 0:
        raise ValueError("amount must be positive")

    priv, pub = derive_priv_pub(mnemonic, derivation_path)
    my_h160 = hash160(pub)
    dest_h160 = h160_from_addr(to_addr)

    servers = servers or DEFAULT_SERVERS
    if use_ssl is None:
        use_ssl = True  # defaults are TLS

    cli, _chosen = connect_any(servers, use_ssl, timeout, insecure, cafile, fingerprint)
    try:
        spk = p2pkh_script(my_h160)
        sh = electrum_scripthash(spk)
        utxos = cli.request("blockchain.scripthash.listunspent", [sh])
        if not utxos:
            raise RuntimeError("no UTXOs for the derived address")

        raw_hex, _txid_local, _fee_atoms, _change_atoms, _size_bytes = build_and_sign(
            priv, pub, utxos, dest_h160, int(amount_atoms), fee_per_byte, my_h160
        )
        txid_net = cli.request("blockchain.transaction.broadcast", [raw_hex])
        return txid_net, raw_hex
    finally:
        cli.close()