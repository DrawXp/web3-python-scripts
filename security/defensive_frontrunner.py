import os
import sys
import threading
import time
import json
import logging
from queue import Queue
import websocket 
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

# Logger configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Environment Variables
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
RPC_MONITOR_WSS = os.getenv("RPC_MONITOR_WSS") # e.g., Chainstack WSS
RPC_ACTION_WSS = os.getenv("RPC_ACTION_WSS")   # e.g., DRPC WSS
SAFE_WALLET = os.getenv("SAFE_WALLET_ADDRESS")
TARGET_WALLET = os.getenv("TARGET_WALLET_ADDRESS")

if not all([PRIVATE_KEY, RPC_MONITOR_WSS, RPC_ACTION_WSS, SAFE_WALLET, TARGET_WALLET]):
    logging.error("Missing environment variables. Check your .env file.")
    sys.exit(1)

# Protocol Configuration
CONFIG = {
    "chainId": 2020,  # Ronin Mainnet
    "gas_increment_gwei": 20
}

# Web3 Connection for Actions
w3_action = Web3(Web3.LegacyWebSocketProvider(RPC_ACTION_WSS))
if not w3_action.is_connected():
    logging.critical("Failed to connect to Action RPC.")
    sys.exit(1)

account = w3_action.eth.account.from_key(PRIVATE_KEY)

# Safe Addresses Whitelist (Checksum)
SAFE_ADDRESSES = {
    Web3.to_checksum_address(SAFE_WALLET).lower(),
    Web3.to_checksum_address(os.getenv("EXTRA_WALLET_1", "0x0")).lower()
}

MONITORED_WALLET = Web3.to_checksum_address(TARGET_WALLET).lower()

# Thread Synchronization
threat_queue = Queue()
action_lock = threading.Lock()

def monitor_mempool():
    """
    WebSocket listener for the 'newPendingTransactions' subscription.
    Acts as the PRODUCER thread.
    """
    def on_message(ws, message):
        try:
            data = json.loads(message)
            if data.get("method") == "eth_subscription":
                process_event(data)
        except Exception as e:
            logging.error(f"Error parsing message: {e}")

    def on_error(ws, error):
        logging.error(f"WebSocket Error: {error}")

    def on_close(ws, close_status_code, close_msg):
        logging.warning("WebSocket connection closed. Reconnecting...")
        time.sleep(2)
        monitor_mempool() # Simple reconnection logic

    def on_open(ws):
        logging.info("Connected to Mempool Monitor.")
        sub_request = {
            "id": 1,
            "method": "eth_subscribe",
            "params": ["newPendingTransactions"]
        }
        ws.send(json.dumps(sub_request))

    ws = websocket.WebSocketApp(
        RPC_MONITOR_WSS,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever()

def process_event(event):
    """
    Filters incoming pending transactions.
    If a tx originates from the monitored wallet to an unknown destination,
    it is flagged as malicious.
    """
    tx_hash = event.get("params", {}).get("result")
    if not tx_hash:
        return

    with action_lock:
        try:
            tx = w3_action.eth.get_transaction(tx_hash)
        except Exception:
            return 

    if not tx:
        return

    from_addr = tx.get("from", "").lower()
    to_addr = tx.get("to", "").lower()

    if from_addr == MONITORED_WALLET:
        if tx.get("blockNumber") is not None:
            return 

        if to_addr not in SAFE_ADDRESSES:
            logging.warning(f"Malicious TX detected: {tx_hash} -> Destination: {to_addr}")
            threat_queue.put(tx)

def transaction_worker():
    """
    Consumes threats from the queue and executes defensive cancellations (Front-running).
    Acts as the CONSUMER thread.
    """
    logging.info("Action Worker started...")
    while True:
        tx = threat_queue.get()
        if not tx:
            continue

        try:
            original_gas_price = tx["gasPrice"]
            new_gas_price = original_gas_price + w3_action.to_wei(CONFIG["gas_increment_gwei"], "gwei")
            nonce = tx["nonce"]

            cancel_tx = {
                "chainId": CONFIG["chainId"],
                "nonce": nonce,
                "to": SAFE_ADDRESSES.copy().pop(), # Send to self/safe wallet
                "value": 0,
                "gas": 21000,
                "gasPrice": new_gas_price,
            }

            signed_tx = account.sign_transaction(cancel_tx)
            
            with action_lock:
                tx_hash = w3_action.eth.send_raw_transaction(signed_tx.raw_transaction)
                logging.info(f"🛡️ Defense TX Sent! Hash: {tx_hash.hex()} | Gas Price: {new_gas_price}")

        except Exception as e:
            logging.error(f"Failed to send defense transaction: {e}")
        finally:
            threat_queue.task_done()

if __name__ == "__main__":
    logging.info("Starting Defensive Security Module...")
    
    # Daemon threads ensure the program exits cleanly when main finishes
    monitor_thread = threading.Thread(target=monitor_mempool, daemon=True)
    worker_thread = threading.Thread(target=transaction_worker, daemon=True)
    
    monitor_thread.start()
    worker_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping services...")
        sys.exit(0)
