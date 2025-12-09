import os
import sys
import time
import threading
import logging
from web3 import Web3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class ValidatorExitBot:
    """
    Automates the process of undelegating assets from a Validator contract
    and sweeping the returned funds to a cold wallet.
    
    Features:
    - High-frequency polling using 'estimateGas' to detect epoch changes.
    - Automated fund sweeping with configurable thresholds.
    - Custom Gas strategy for front-running standard withdrawals.
    """

    def __init__(self):
        # 1. Critical Configuration
        self.private_key = os.getenv("PRIVATE_KEY")
        self.rpc_url = os.getenv("RPC_URL_AUTH") 
        self.staking_contract_addr = os.getenv("STAKING_CONTRACT_ADDRESS")
        self.destination_addr = os.getenv("COLD_WALLET_ADDRESS")
        self.target_validator_pool = os.getenv("TARGET_POOL_ID")
        
        # 2. Operational Parameters (Loaded from env or defaults)
        try:
            self.unstake_amount_wei = int(os.getenv("UNSTAKE_AMOUNT_WEI", 0))
            self.min_balance_threshold = Web3.to_wei(float(os.getenv("MIN_BALANCE_RESERVE", "1.0")), "ether")
            # Gas Strategy: Priority fee for the undelegate action
            self.priority_gas_price = Web3.to_wei(int(os.getenv("PRIORITY_GAS_GWEI", "50")), "gwei")
        except ValueError as e:
            logging.error(f"Configuration Error: {e}")
            sys.exit(1)

        # Validation
        if not all([self.private_key, self.rpc_url, self.staking_contract_addr]):
            logging.critical("Missing required environment variables.")
            sys.exit(1)

        # 3. Web3 Initialization
        self.w3 = Web3(Web3.LegacyWebSocketProvider(self.rpc_url))
        if not self.w3.is_connected():
            logging.critical("Failed to connect to RPC Provider.")
            sys.exit(1)

        self.account = self.w3.eth.account.from_key(self.private_key)
        self.wallet_address = self.account.address
        
        # 4. Contract Setup
        # Using a minimal ABI to reduce file size and complexity
        self.staking_abi = [
            {
                "inputs": [
                    {"internalType": "address", "name": "poolId", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"}
                ],
                "name": "undelegate",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        self.staking_contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.staking_contract_addr),
            abi=self.staking_abi
        )

    def run_cycle(self):
        """
        Main execution loop.
        Monitors contract state and executes exit strategy when conditions are met.
        """
        logging.info(f"Bot started. Monitoring Validator Pool: {self.target_validator_pool}...")
        
        while True:
            # --- PHASE 1: EXIT STRATEGY (Polling) ---
            try:
                # We use estimate_gas as a lightweight check to see if the transaction 
                # will succeed (i.e., if the epoch/lock period has ended).
                contract_func = self.staking_contract.functions.undelegate(
                    Web3.to_checksum_address(self.target_validator_pool), 
                    self.unstake_amount_wei
                )
                
                # If this raises an exception, the contract is strictly reverting (locked)
                gas_limit = contract_func.estimate_gas({"from": self.wallet_address})
                
                logging.info(f"Unlocking detected! Estimated Gas: {gas_limit}")
                
                # Construct and sign the transaction
                tx_data = contract_func.build_transaction({
                    "chainId": 2020, 
                    "nonce": self.w3.eth.get_transaction_count(self.wallet_address),
                    "gas": gas_limit,
                    "gasPrice": self.priority_gas_price
                })
                
                signed_tx = self.account.sign_transaction(tx_data)
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                logging.info(f"SUCCESS: Undelegate TX submitted: {tx_hash.hex()}")

            except Exception:
                # Ideally catch specific Web3 reversion errors here.
                # Passing silently is acceptable for high-frequency polling logic.
                pass

            # --- PHASE 2: SWEEP LOGIC ---
            self._sweep_funds()

            # Throttle to prevent RPC rate limiting
            time.sleep(0.5) 

    def _sweep_funds(self):
        """
        Checks wallet balance and transfers excess funds to the cold wallet.
        """
        try:
            balance = self.w3.eth.get_balance(self.wallet_address)
            
            if balance > self.min_balance_threshold:
                sweep_amount = balance - self.min_balance_threshold
                
                # Simple transfer logic
                tx_sweep = {
                    "chainId": 2020,
                    "nonce": self.w3.eth.get_transaction_count(self.wallet_address),
                    "to": Web3.to_checksum_address(self.destination_addr),
                    "value": sweep_amount,
                    "gas": 21000,
                    "gasPrice": self.w3.eth.gas_price # Use market rate for sweep
                }
                
                signed_sweep = self.account.sign_transaction(tx_sweep)
                sweep_hash = self.w3.eth.send_raw_transaction(signed_sweep.raw_transaction)
                
                logging.info(f"Funds Swept: {self.w3.from_wei(sweep_amount, 'ether')} RON -> {self.destination_addr}")

        except Exception as e:
            logging.error(f"Sweep Check Failed: {e}")

if __name__ == "__main__":
    bot = ValidatorExitBot()
    
    # Run in a separate thread to allow for future expansion (e.g., API listeners)
    worker = threading.Thread(target=bot.run_cycle, daemon=True)
    worker.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down bot services...")
        sys.exit(0)
