import os
import sys
import time
import logging
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class TimeLockedClaimer:
    """
    Block-Synchronized Claim Bot.
    
    Monitors the blockchain height to execute a smart contract interaction 
    (e.g., claiming staking rewards) at a precise block number. 
    It persists until a specific balance threshold is met (confirmation of success).
    """

    def __init__(self):
        # --- Network Configuration ---
        self.rpc_url = os.getenv("CHILIZ_RPC_URL", "https://rpc.ankr.com/chiliz")
        self.chain_id = int(os.getenv("CHILIZ_CHAIN_ID", 88888))
        self.explorer_url = os.getenv("CHILIZ_EXPLORER", "https://chiliscan.com")
        
        # --- Authentication ---
        self.private_key = os.getenv("CHILIZ_PRIVATE_KEY")
        if not self.private_key:
            logging.critical("Missing CHILIZ_PRIVATE_KEY in .env")
            sys.exit(1)

        # --- Contract Targets ---
        # The contract responsible for distribution/staking
        self.contract_address = Web3.to_checksum_address(os.getenv("TARGET_CONTRACT"))
        # The specific validator or pool address involved in the claim
        self.validator_address = Web3.to_checksum_address(os.getenv("TARGET_VALIDATOR"))
        
        # --- Operational Parameters ---
        self.target_block = int(os.getenv("TARGET_BLOCK_HEIGHT"))
        # Stop bot when balance reaches this amount (Wei)
        self.target_balance_wei = Web3.to_wei(int(os.getenv("TARGET_BALANCE_THRESHOLD", 500)), 'ether')
        
        # Function Selector for 'claim(address)' -> 0x1e83409a
        self.claim_selector = "0x1e83409a"

        # Initialize Web3
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        # POA Middleware is crucial for Chiliz/BSC/Polygon chains
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not self.w3.is_connected():
            logging.critical("Failed to connect to RPC Endpoint.")
            sys.exit(1)

        self.account = self.w3.eth.account.from_key(self.private_key)
        self.sender = self.account.address
        
        logging.info(f"Bot initialized for account: {self.sender}")
        logging.info(f"Target Block: {self.target_block}")

    def _encode_address_param(self, addr: str) -> str:
        """Encodes an address to 32-byte hex format for raw calldata."""
        return addr.replace("0x", "").lower().rjust(64, "0")

    def _build_calldata(self) -> str:
        """Constructs the raw data payload: selector + encoded validator address."""
        return self.claim_selector + self._encode_address_param(self.validator_address)

    def _get_gas_price(self):
        """Fetches current gas price."""
        return self.w3.eth.gas_price

    def wait_for_block(self):
        """Polls the network until the target block height is reached."""
        logging.info("Starting block monitor...")
        
        while True:
            try:
                current_block = self.w3.eth.get_block("latest").number
                
                if current_block >= self.target_block:
                    logging.info(f"Target block reached! Current: {current_block} >= Target: {self.target_block}")
                    return
                
                logging.info(f"Current Block: {current_block} | Waiting for {self.target_block}...")
                time.sleep(1.5) # Chiliz block time is approx 3s
                
            except Exception as e:
                logging.error(f"Error fetching block: {e}")
                time.sleep(1)

    def execute_claim_loop(self):
        """
        Continuously attempts to claim rewards until the wallet balance reflects the success.
        This handles cases where the first tx might fail or be pending.
        """
        calldata = self._build_calldata()
        
        while True:
            # Check exit condition (Did we get the money?)
            balance = self.w3.eth.get_balance(self.sender)
            if balance >= self.target_balance_wei:
                logging.info(f"💰 Target Balance Reached: {self.w3.from_wei(balance, 'ether')} CHZ. Exiting.")
                break
            
            logging.info(f"Balance: {self.w3.from_wei(balance, 'ether')} CHZ. Attempting claim...")

            try:
                nonce = self.w3.eth.get_transaction_count(self.sender)
                
                tx = {
                    "chainId": self.chain_id,
                    "from": self.sender,
                    "to": self.contract_address,
                    "value": 0,
                    "gas": 250000, # Hardcoded buffer based on previous traces
                    "gasPrice": self._get_gas_price(),
                    "nonce": nonce,
                    "data": calldata
                }

                signed_tx = self.account.sign_transaction(tx)
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                logging.info(f"🚀 Tx Sent: {tx_hash.hex()}")
                
                # Optional: Wait briefly to not spam RPC too hard, 
                # but fast enough to retry if needed.
                time.sleep(2) 

            except Exception as e:
                logging.error(f"Transaction failed: {e}")
                time.sleep(1)

    def run(self):
        self.wait_for_block()
        self.execute_claim_loop()

if __name__ == "__main__":
    bot = TimeLockedClaimer()
    try:
        bot.run()
    except KeyboardInterrupt:
        logging.info("Bot stopped by user.")
        sys.exit(0)
