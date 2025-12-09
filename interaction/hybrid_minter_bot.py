import os
import sys
import time
import random
import json
import traceback
from typing import Optional, Tuple, List
import requests
from dotenv import load_dotenv
from web3 import Web3
from web3.types import TxParams
from web3.exceptions import TimeExhausted
from eth_abi import encode as abi_encode

# ===============================================================
# CONFIGURATION
# ===============================================================
load_dotenv()

# API Configuration
AF_API_BASE = "https://api.aquaflux.pro"
# Load JWT from environment variable for security
AF_JWT = os.getenv("AF_JWT") 
REQUESTED_NFT_TYPE = 0

# Network Configuration (Pharos Testnet)
RPC_URL  = "https://testnet.dplabs-internal.com"
CHAIN_ID = 688688
CONTRACT_ADDRESS = "0xCc8cF44E196CaB28DBA2d514dc7353af0eFb370E"

# Load Private Key
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
if not PRIVATE_KEY:
    print("[ERROR] PRIVATE_KEY not found in .env file.")
    sys.exit(1)

if not AF_JWT:
    print("[ERROR] AF_JWT not found in .env file. Please add your Bearer token.")
    sys.exit(1)

# ===============================================================
# WEB3 INITIALIZATION
# ===============================================================
w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 60}))
if not w3.is_connected():
    print("[ERROR] Failed to connect to RPC.")
    sys.exit(1)

account = w3.eth.account.from_key(PRIVATE_KEY)
SENDER = Web3.to_checksum_address(account.address)
CONTRACT = Web3.to_checksum_address(CONTRACT_ADDRESS)

print(f"[INIT] Sender: {SENDER} | Chain ID: {w3.eth.chain_id}")

# ===============================================================
# TRANSACTION DATA (RAW CALLDATA)
# ===============================================================
# TX1: Initial interaction (Method ID: 0x48c54b9d)
TX1 = {"label": "TX1", "to": CONTRACT, "data": "0x48c54b9d", "value": 0}
# TX2: Secondary interaction (Method ID: 0x7905642a...)
TX2 = {"label": "TX2", "to": CONTRACT, "data": "0x7905642a0000000000000000000000000000000000000000000000056bc75e2d63100000", "value": 0}
# TX3 Selector: mintWithSignature or similar (Method ID: 0x75e7e053)
TX3_SELECTOR = "0x75e7e053"

# ===============================================================
# HELPER FUNCTIONS
# ===============================================================

def build_fees() -> dict:
    """Calculates gas fees supporting both EIP-1559 and Legacy."""
    try: 
        base = w3.eth.get_block("latest").get("baseFeePerGas")
    except Exception: 
        base = None
    
    try: 
        prio = w3.eth.max_priority_fee
    except Exception: 
        prio = None
        
    if base is not None and prio is not None:
        mp = int(prio)
        mf = int(base * 2 + mp)
        return {"maxPriorityFeePerGas": mp, "maxFeePerGas": mf}
    
    return {"gasPrice": int(w3.eth.gas_price)}

def estimate_with_buffer(tx: TxParams, buf: float = 1.20, fallback: int = 400_000) -> int:
    """Estimates gas with a safety buffer."""
    try: 
        return int(w3.eth.estimate_gas(tx) * buf)
    except Exception: 
        return fallback

def raw_tx_bytes(signed):
    """Extracts raw bytes from signed transaction object."""
    return getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction", None) or getattr(signed, "raw", None)

def _is_replay_error(e: Exception) -> bool:
    """Detects nonce-related errors from RPC response."""
    s = str(e).lower()
    return any(k in s for k in ["tx_replay", "nonce too low", "replacement transaction underpriced", "already known", "errcode: 113"])

def send_tx(label: str, to_addr: str, data_hex: str, value_wei: int, nonce: int):
    """Builds, signs, and broadcasts a transaction."""
    tx: TxParams = {
        "from": SENDER, 
        "to": Web3.to_checksum_address(to_addr), 
        "data": data_hex, 
        "value": int(value_wei), 
        "chainId": CHAIN_ID, 
        "nonce": nonce
    }
    
    tx.update(build_fees())
    tx["gas"] = estimate_with_buffer(tx)
    
    try:
        signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        txh = w3.eth.send_raw_transaction(raw_tx_bytes(signed))
        print(f"[{label}] Broadcasted: {txh.hex()} (nonce={nonce})")
    except Exception as e:
        if _is_replay_error(e):
            current = w3.eth.get_transaction_count(SENDER, "pending")
            print(f"[{label}] Replay/Nonce conflict. Pending nonce: {current}. Error: {e}")
            return None, current
        raise

    try:
        rcpt = w3.eth.wait_for_transaction_receipt(txh, timeout=120)
        print(f"[{label}] Confirmed. Block: {rcpt.blockNumber} | Status: {rcpt.status} | Gas Used: {rcpt.gasUsed}")
        if rcpt.status != 1:
            raise RuntimeError(f"{label} reverted on-chain.")
    except TimeExhausted:
        print(f"[{label}] Confirmation timeout. Hash: {txh.hex()}")
    except Exception as e:
        print(f"[{label}] Error waiting for receipt: {e}")
        raise
        
    return txh.hex(), nonce

# ===============================================================
# API INTERACTION (Web2 Authentication)
# ===============================================================

def _auth_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {AF_JWT}",
        "Origin": "https://playground.aquaflux.pro",
        "Referer": "https://playground.aquaflux.pro/",
    }

def post_json(url: str, payload: Optional[dict], timeout: int = 20) -> requests.Response:
    data = json.dumps(payload) if payload is not None else None
    r = requests.post(url, data=data, headers=_auth_headers(), timeout=timeout)
    return r

def check_token_holding() -> dict:
    url = AF_API_BASE.rstrip("/") + "/api/v1/users/check-token-holding"
    r = post_json(url, payload=None)
    if r.status_code >= 400:
        print(f"[check-token-holding] Error: {r.status_code} {r.text}")
        r.raise_for_status()
    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text}
    print("[check-token-holding] OK.")
    return data

_SIGNATURE_CANDIDATES: List[str] = [
    "/api/v1/users/get-signature",
    "/api/v1/get-signature",
    "/api/get-signature",
    "/api/v1/users/signature",
    "/api/v1/signature",
]

def find_signature_endpoint() -> str:
    base = AF_API_BASE.rstrip("/")
    payload = {"walletAddress": SENDER, "requestedNftType": int(REQUESTED_NFT_TYPE)}
    
    for path in _SIGNATURE_CANDIDATES:
        url = base + path
        try:
            r = post_json(url, payload)
            if 200 <= r.status_code < 300:
                print(f"[discover] Endpoint found: {url}")
                return url
            else:
                print(f"[discover] {url} -> {r.status_code}")
        except Exception as e:
            print(f"[discover] {url} failed: {e}")
            
    raise RuntimeError("Could not discover signature endpoint. Check Developer Tools.")

def fetch_server_sig(sig_endpoint: str, wallet: str, nft_type: int) -> Tuple[int, bytes, str]:
    payload = {"walletAddress": wallet, "requestedNftType": int(nft_type)}
    r = post_json(sig_endpoint, payload)
    
    if r.status_code >= 400:
        print(f"[get-signature] Error: {r.status_code} {r.text}")
        r.raise_for_status()
        
    data = r.json()
    body = data.get("data", data)
    
    ts  = body.get("timestamp") or body.get("ts") or body.get("expiresAt")
    sig = body.get("signature") or body.get("sig")
    ref = body.get("referrer")  or "0x0000000000000000000000000000000000000000"
    
    if ts is None or sig is None:
        raise RuntimeError(f"Unexpected response from get-signature: {data}")
        
    ts = int(ts)
    if ts > 10**12:  # Convert ms to seconds if necessary
        ts //= 1000
        
    sig_bytes = bytes.fromhex(sig.removeprefix("0x"))
    ref = Web3.to_checksum_address(ref)
    
    print(f"[get-signature] Timestamp={ts} SigLen={len(sig_bytes)} Referrer={ref}")
    return ts, sig_bytes, ref

def build_tx3_calldata_dynamic(sig_endpoint: str, wallet: str, nft_type: int) -> str:
    # 1. Verification (Backend check)
    try:
        check_token_holding()
    except Exception as e:
        print("[warn] check-token-holding failed (proceeding anyway):", e)
        
    # 2. Fetch signed package
    ts, sig_bytes, referrer = fetch_server_sig(sig_endpoint, wallet, nft_type)
    
    # 3. ABI Encode arguments
    enc = abi_encode(["address", "uint256", "bytes"], [referrer, ts, sig_bytes])
    return TX3_SELECTOR + enc.hex()

def simulate_call(to_addr: str, data_hex: str, from_addr: Optional[str] = None) -> bool:
    """Performs an eth_call to check for reverts before broadcasting."""
    call = {"to": Web3.to_checksum_address(to_addr), "data": data_hex}
    if from_addr: call["from"] = Web3.to_checksum_address(from_addr)
    try:
        w3.eth.call(call, block_identifier="latest")
        return True
    except Exception as e:
        print("[sim] eth_call reverted/error:", e)
        return False

# ===============================================================
# MAIN EXECUTION
# ===============================================================

def main():
    # Phase 0: Discovery
    sig_endpoint = find_signature_endpoint()

    nonce = w3.eth.get_transaction_count(SENDER, "pending")
    print(f"[nonce] Initial (pending) = {nonce}")

    # Phase 1: TX1 (Static Handshake)
    for attempt in range(1, 6):
        res = None
        try:
            res = send_tx(TX1["label"], TX1["to"], TX1["data"], TX1["value"], nonce)
            if res is None:
                nonce = w3.eth.get_transaction_count(SENDER, "pending")
                time.sleep(0.8 * attempt); continue
            _, _ = res; nonce += 1; break
        except Exception as e:
            print(f"[TX1] Error {attempt}/5: {repr(e)}"); traceback.print_exc()
            nonce = w3.eth.get_transaction_count(SENDER, "pending"); time.sleep(1.2 * attempt)

    pause = random.uniform(10, 20)
    print(f"[Wait] Sleeping for {pause:.1f}s...")
    time.sleep(pause)

    # Phase 2: TX2 (Static Interaction)
    for attempt in range(1, 6):
        res = None
        try:
            res = send_tx(TX2["label"], TX2["to"], TX2["data"], TX2["value"], nonce)
            if res is None:
                nonce = w3.eth.get_transaction_count(SENDER, "pending")
                time.sleep(0.8 * attempt); continue
            _, _ = res; nonce += 1; break
        except Exception as e:
            print(f"[TX2] Error {attempt}/5: {repr(e)}"); traceback.print_exc()
            nonce = w3.eth.get_transaction_count(SENDER, "pending"); time.sleep(1.2 * attempt)

    pause = random.uniform(10, 20)
    print(f"[Wait] Sleeping for {pause:.1f}s...")
    time.sleep(pause)

    # Phase 3: TX3 (Dynamic Mint with Signature)
    for attempt in range(1, 6):
        try:
            data_tx3 = build_tx3_calldata_dynamic(sig_endpoint, SENDER, REQUESTED_NFT_TYPE)
            
            # Dry-run / Simulation
            if not simulate_call(CONTRACT, data_tx3, from_addr=SENDER):
                print("[TX3] Simulation indicated revert. Retrying...")
                time.sleep(1.2 * attempt); continue
                
            res = send_tx("TX3", CONTRACT, data_tx3, 0, nonce)
            if res is None:
                nonce = w3.eth.get_transaction_count(SENDER, "pending")
                time.sleep(0.8 * attempt); continue
            _, _ = res; nonce += 1; break
        except Exception as e:
            print(f"[TX3] Error {attempt}/5: {repr(e)}"); traceback.print_exc()
            nonce = w3.eth.get_transaction_count(SENDER, "pending"); time.sleep(1.2 * attempt)

    print("✔️ Sequence completed successfully.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user.")
    except Exception:
        traceback.print_exc(); sys.exit(1)
