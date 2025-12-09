import os
import sys
import time
import re
import logging
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from web3.exceptions import TimeExhausted
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class LiquidityProvisioner:
    """
    Automated Liquidity Provisioning Module.
    
    Features:
    - Pre-flight simulation using eth_call (prevents failed tx fees).
    - Dynamic gas estimation (EIP-1559 & Legacy support).
    - Revert reason decoding for debugging smart contract errors.
    - Automatic approval handling.
    """

    def __init__(self):
        # 1. Load Configuration
        self.rpc_url = os.getenv("RPC_URL")
        self.private_key = os.getenv("PRIVATE_KEY")
        
        # Target Contracts
        self.router_address = os.getenv("ROUTER_ADDRESS")
        self.token_a_address = os.getenv("TOKEN_A_ADDRESS")
        self.token_b_address = os.getenv("TOKEN_B_ADDRESS")
        
        # Operational Config
        try:
            self.target_amount_a = float(os.getenv("TARGET_AMOUNT_A", "0.0"))
            self.slippage_bps = int(os.getenv("SLIPPAGE_BPS", "50")) # 0.5% default
            self.pool_fee_bps = int(os.getenv("POOL_FEE_BPS", "30")) # 0.3%
            self.tx_deadline = int(os.getenv("TX_DEADLINE", "1200"))
        except ValueError as e:
            logging.critical(f"Configuration Error: {e}")
            sys.exit(1)

        # Validation
        if not all([self.rpc_url, self.private_key, self.router_address, self.token_a_address, self.token_b_address]):
            logging.critical("Missing required environment variables.")
            sys.exit(1)

        # 2. Web3 Initialization
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 60}))
        
        # Middleware for PoA chains (e.g., Polygon, BSC, Testnets)
        # Note: Adjust logic if using Web3.py v7+ strict strict modes
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not self.w3.is_connected():
            logging.critical("Failed to connect to RPC.")
            sys.exit(1)

        self.account = self.w3.eth.account.from_key(self.private_key)
        self.wallet_address = self.account.address
        
        # 3. Contract Setup
        self.router_abi = [
            {"inputs":[{"name":"amountIn","type":"uint256"},{"name":"path","type":"address[]"},{"name":"fees","type":"uint256[]"}],"name":"getAmountsOut","outputs":[{"type":"uint256[]"}],"stateMutability":"view","type":"function"},
            {"inputs":[{"name":"tokenA","type":"address"},{"name":"tokenB","type":"address"},{"name":"fee","type":"uint256"},{"name":"amountADesired","type":"uint256"},{"name":"amountBDesired","type":"uint256"},{"name":"amountAMin","type":"uint256"},{"name":"amountBMin","type":"uint256"},{"name":"to","type":"address"},{"name":"deadline","type":"uint256"}],"name":"addLiquidity","outputs":[{"type":"uint256"},{"type":"uint256"},{"type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
        ]
        self.erc20_abi = [
            {"inputs":[],"name":"decimals","outputs":[{"type":"uint8"}],"stateMutability":"view","type":"function"},
            {"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
            {"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
            {"inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"name":"approve","outputs":[{"type":"bool"}],"stateMutability":"nonpayable","type":"function"},
        ]

        self.router = self.w3.eth.contract(address=Web3.to_checksum_address(self.router_address), abi=self.router_abi)
        self.token_a = self.w3.eth.contract(address=Web3.to_checksum_address(self.token_a_address), abi=self.erc20_abi)
        self.token_b = self.w3.eth.contract(address=Web3.to_checksum_address(self.token_b_address), abi=self.erc20_abi)

    def _get_gas_params(self):
        """Dynamic gas strategy: supports EIP-1559 and Legacy."""
        try:
            latest_block = self.w3.eth.get_block("latest")
            base_fee = latest_block.get("baseFeePerGas")
            
            if base_fee:
                priority_fee = self.w3.eth.max_priority_fee
                max_fee = int(base_fee * 1.5 + priority_fee) # 50% buffer on base fee
                return {"maxPriorityFeePerGas": priority_fee, "maxFeePerGas": max_fee}
        except Exception:
            pass
            
        return {"gasPrice": int(self.w3.eth.gas_price * 1.1)}

    def _decode_revert_reason(self, error):
        """
        Attempts to decode the EVM revert reason from a failed simulation/transaction.
        Crucial for debugging 'execution reverted' errors.
        """
        error_str = str(error)
        match = re.search(r"(0x[0-9a-fA-F]{8}[0-9a-fA-F]*)", error_str)
        if match:
            data = match.group(1)
            # Check for standard Error(string) signature: 0x08c379a0
            if data.startswith("0x08c379a0"):
                try:
                    byte_data = bytes.fromhex(data[10:])
                    length = int.from_bytes(byte_data[64:96], "big")
                    return byte_data[96:96+length].decode(errors="replace")
                except Exception:
                    pass
        return "Unknown Revert Reason"

    def execute_provision(self):
        logging.info(f"Starting Liquidity Provision for {self.target_amount_a} Token A...")

        # 1. Fetch Decimals
        decimals_a = self.token_a.functions.decimals().call()
        decimals_b = self.token_b.functions.decimals().call()
        amount_a_wei = int(self.target_amount_a * (10**decimals_a))

        # 2. Get Quote (Market Price)
        # We need to know how much Token B corresponds to our Token A
        try:
            amounts_out = self.router.functions.getAmountsOut(
                amount_a_wei,
                [self.token_a.address, self.token_b.address],
                [self.pool_fee_bps]
            ).call()
            amount_b_desired = amounts_out[-1]
            logging.info(f"Quote Received: {amount_b_desired} Wei (Token B)")
        except Exception as e:
            logging.error(f"Failed to fetch quote via Router. Ensure pool exists. Error: {e}")
            return

        # 3. Calculate Slippage Min
        amount_a_min = amount_a_wei * (10000 - self.slippage_bps) // 10000
        amount_b_min = amount_b_desired * (10000 - self.slippage_bps) // 10000
        deadline = int(time.time()) + self.tx_deadline

        # 4. Handle Approvals
        nonce = self.w3.eth.get_transaction_count(self.wallet_address, "pending")
        tokens = [
            (self.token_a, amount_a_wei, "Token A"), 
            (self.token_b, amount_b_desired, "Token B")
        ]

        for contract, amount, label in tokens:
            allowance = contract.functions.allowance(self.wallet_address, self.router.address).call()
            if allowance < amount:
                logging.info(f"Approving {label}...")
                tx = contract.functions.approve(self.router.address, amount).build_transaction({
                    "from": self.wallet_address,
                    "nonce": nonce,
                    "chainId": self.w3.eth.chain_id,
                    "gas": 100000,
                    **self._get_gas_params()
                })
                signed = self.account.sign_transaction(tx)
                self.w3.eth.send_raw_transaction(signed.raw_transaction)
                nonce += 1 # Increment nonce locally for the next tx
                time.sleep(2) # Brief pause for propagation
            else:
                logging.info(f"{label} allowance sufficient.")

        # 5. Add Liquidity (Simulation -> Execution)
        logging.info("Simulating addLiquidity transaction...")
        
        liquidity_func = self.router.functions.addLiquidity(
            self.token_a.address, self.token_b.address, self.pool_fee_bps,
            amount_a_wei, amount_b_desired,
            amount_a_min, amount_b_min,
            self.wallet_address, deadline
        )

        try:
            # Simulation (eth_call)
            liquidity_func.call({"from": self.wallet_address})
            logging.info("Simulation Successful. Broadcasting transaction...")
            
            # Build Real Transaction
            tx = liquidity_func.build_transaction({
                "from": self.wallet_address,
                "nonce": nonce,
                "chainId": self.w3.eth.chain_id,
                "gas": 500000, # Fallback limit
                **self._get_gas_params()
            })
            
            signed = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            logging.info(f"Liquidity Added! TX Hash: {tx_hash.hex()}")
            
        except Exception as e:
            reason = self._decode_revert_reason(e)
            logging.error(f"Transaction Simulation Failed. Revert Reason: {reason}")
            logging.debug(f"Full Error: {e}")

if __name__ == "__main__":
    provisioner = LiquidityProvisioner()
    try:
        provisioner.execute_provision()
    except KeyboardInterrupt:
        sys.exit(0)
