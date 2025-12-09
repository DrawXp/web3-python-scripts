import os
import sys
import time
import math
import random
import traceback
import logging
from dotenv import load_dotenv
from web3 import Web3
from web3.types import TxParams
from eth_abi import encode as abi_encode
from eth_account.messages import encode_typed_data
from eth_account import Account

# Load environment variables
load_dotenv()

# Configure Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# ===============================================================
# CONFIGURATION
# ===============================================================
CHAIN_ID = 10143
RPC_URL  = "https://monad-testnet.drpc.org"

# Target Tokens & Router
TOKEN_ADDRESS = Web3.to_checksum_address(os.getenv("MONAD_TOKEN_ADDRESS"))
ROUTER_ADDRESS = Web3.to_checksum_address(os.getenv("MONAD_ROUTER_ADDRESS"))

# Trading Parameters
SELL_FRACTION       = 0.25 # Sell 25% of holdings
MIN_OUT_TOKENS      = 0    # Slippage tolerance (0 = accept any amount)
APPROVE_GAS_LIMIT   = 80000
SELL_GAS_LIMIT      = 230000
GAS_BUFFER          = 0.20
GAS_PRICE_FLOOR_GWEI = 50

# Private Key Loader
PRIVATE_KEY = os.getenv("MONAD_PRIVATE_KEY")
if not PRIVATE_KEY:
    logging.critical("Missing MONAD_PRIVATE_KEY in .env")
    sys.exit(1)

# Web3 Connection
w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 60}))
if not w3.is_connected():
    logging.critical("Failed to connect to Monad RPC")
    sys.exit(1)

account = w3.eth.account.from_key(PRIVATE_KEY)
OWNER = Web3.to_checksum_address(account.address)

# ===============================================================
# HELPER FUNCTIONS
# ===============================================================

def get_gas_price() -> int:
    """Calculates gas price with a floor limit."""
    try:
        gp = int(w3.eth.gas_price)
    except Exception:
        gp = w3.to_wei(GAS_PRICE_FLOOR_GWEI, "gwei")
    return max(gp, w3.to_wei(GAS_PRICE_FLOOR_GWEI, "gwei"))

def estimate_gas_with_buffer(tx: TxParams, fallback: int) -> int:
    """Estimates gas usage and applies a safety multiplier."""
    try:
        est = w3.eth.estimate_gas(tx)
        return math.ceil(est * (1.0 + GAS_BUFFER))
    except Exception:
        return fallback

def call_contract_view(to: str, data: str) -> int:
    """Performs a raw eth_call to read contract state."""
    raw = w3.eth.call({"to": to, "data": data}, "latest")
    return int.from_bytes(raw[-32:], "big") if raw else 0

def get_token_balance(token: str, owner: str) -> int:
    # selector: balanceOf(address) -> 0x70a08231
    return call_contract_view(token, "0x70a08231" + "0"*24 + owner[2:])

def get_allowance(token: str, owner: str, spender: str) -> int:
    # selector: allowance(address,address) -> 0xdd62ed3e
    data = "0xdd62ed3e" + ("0"*24 + owner[2:]) + ("0"*24 + spender[2:])
    return call_contract_view(token, data)

def get_nonces(token: str, owner: str) -> int:
    """Attempts to fetch EIP-2612 nonces for Permit."""
    try:
        # selector: nonces(address) -> 0x7ecebe00
        data = "0x7ecebe00" + ("0"*24 + owner[2:])
        return call_contract_view(token, data)
    except Exception:
        # Fallback for some implementations: _nonces(address)
        return 0

def send_transaction(tx: TxParams, label: str) -> bool:
    """Signs and broadcasts a transaction, waiting for receipt."""
    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    logging.info(f"[{label}] Broadcasted: {tx_hash.hex()}")
    
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        logging.info(f"[{label}] Confirmed. Block: {receipt.blockNumber} | Status: {receipt.status}")
        return receipt.status == 1
    except Exception as e:
        logging.error(f"[{label}] Transaction failed/timeout: {e}")
        return False

# ===============================================================
# ENCODING & SIGNING (EIP-2612 PERMIT)
# ===============================================================

def encode_approve(spender: str, amount: int) -> str:
    return "0x095ea7b3" + abi_encode(["address","uint256"], [spender, amount]).hex()

def encode_sell_tokens(token: str, amount: int, min_out: int) -> str:
    # Custom router function selector: 0x6a272462 (e.g., swapExactTokensForETH)
    return "0x6a272462" + abi_encode(["address","uint256","uint256"], [token, amount, min_out]).hex()

def sign_permit(owner: str, spender: str, value: int, nonce: int, deadline: int):
    """Generates EIP-712 signature for Gasless Approvals (Permit)."""
    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name":"name","type":"string"},
                {"name":"version","type":"string"},
                {"name":"chainId","type":"uint256"},
                {"name":"verifyingContract","type":"address"},
            ],
            "Permit": [
                {"name":"owner","type":"address"},
                {"name":"spender","type":"address"},
                {"name":"value","type":"uint256"},
                {"name":"nonce","type":"uint256"},
                {"name":"deadline","type":"uint256"},
            ],
        },
        "primaryType": "Permit",
        "domain": {
            "name": "$DesertFrog", # Dynamic fetching would be better in prod
            "version": "1",
            "chainId": CHAIN_ID,
            "verifyingContract": TOKEN_ADDRESS,
        },
        "message": {
            "owner": owner,
            "spender": spender,
            "value": int(value),
            "nonce": int(nonce),
            "deadline": int(deadline),
        },
    }
    
    signed_msg = Account.sign_message(encode_typed_data(full_message=typed_data), private_key=PRIVATE_KEY)
    return signed_msg.v, signed_msg.r.to_bytes(32, "big"), signed_msg.s.to_bytes(32, "big")

def encode_permit_calldata(owner, spender, value, deadline, v, r, s):
    # selector: permit(...) -> 0xd505accf
    selector = "0xd505accf"
    encoded_args = abi_encode(
        ["address","address","uint256","uint256","uint8","bytes32","bytes32"],
        [owner, spender, value, deadline, v, r, s]
    ).hex()
    return selector + encoded_args

# ===============================================================
# MAIN EXECUTION FLOW
# ===============================================================

def main():
    logging.info(f"Connected to Monad Testnet | Account: {OWNER}")

    balance = get_token_balance(TOKEN_ADDRESS, OWNER)
    amount_to_sell = int(balance * SELL_FRACTION)
    
    logging.info(f"Token Balance: {balance} | Selling: {amount_to_sell}")

    if amount_to_sell == 0:
        logging.warning("Balance too low or sell amount is 0. Exiting.")
        return

    # Check Allowance
    current_allowance = get_allowance(TOKEN_ADDRESS, OWNER, ROUTER_ADDRESS)
    gas_price = get_gas_price()
    nonce = w3.eth.get_transaction_count(OWNER)

    # --- Step 1: Approve (via Permit or Standard Approve) ---
    if current_allowance < amount_to_sell:
        logging.info("Allowance insufficient. Attempting Permit (Gasless Approval)...")
        
        permit_success = False
        try:
            # Try EIP-2612 Permit
            permit_nonce = get_nonces(TOKEN_ADDRESS, OWNER)
            deadline = int(time.time()) + 600 # 10 minutes
            v, r, s = sign_permit(OWNER, ROUTER_ADDRESS, amount_to_sell, permit_nonce, deadline)
            permit_data = encode_permit_calldata(OWNER, ROUTER_ADDRESS, amount_to_sell, deadline, v, r, s)

            tx_permit = {
                "chainId": CHAIN_ID,
                "from": OWNER,
                "to": TOKEN_ADDRESS,
                "value": 0,
                "data": permit_data,
                "nonce": nonce,
                "gasPrice": gas_price
            }
            tx_permit["gas"] = estimate_gas_with_buffer(tx_permit, APPROVE_GAS_LIMIT)
            
            if send_transaction(tx_permit, "Permit"):
                permit_success = True
                nonce += 1 # Increment nonce for next tx
            
        except Exception as e:
            logging.warning(f"Permit failed or not supported: {e}")

        # Fallback to Standard Approve if Permit failed
        if not permit_success:
            logging.info("Falling back to Standard Approve...")
            tx_approve = {
                "chainId": CHAIN_ID,
                "from": OWNER,
                "to": TOKEN_ADDRESS,
                "value": 0,
                "data": encode_approve(ROUTER_ADDRESS, amount_to_sell),
                "nonce": nonce,
                "gasPrice": gas_price
            }
            tx_approve["gas"] = estimate_gas_with_buffer(tx_approve, APPROVE_GAS_LIMIT)
            
            if not send_transaction(tx_approve, "Approve"):
                logging.error("Approval failed. Aborting.")
                return
            nonce += 1
            
        # Wait a bit for propagation
        time.sleep(random.uniform(2, 5))

    # --- Step 2: Sell / Swap ---
    logging.info("Executing Swap...")
    tx_sell = {
        "chainId": CHAIN_ID,
        "from": OWNER,
        "to": ROUTER_ADDRESS,
        "value": 0,
        "data": encode_sell_tokens(TOKEN_ADDRESS, amount_to_sell, MIN_OUT_TOKENS),
        "nonce": nonce,
        "gasPrice": gas_price
    }
    tx_sell["gas"] = estimate_gas_with_buffer(tx_sell, SELL_GAS_LIMIT)

    if send_transaction(tx_sell, "Sell"):
        logging.info("Swap execution completed successfully.")
    else:
        logging.error("Swap execution failed.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Critical Error: {e}")
        traceback.print_exc()
