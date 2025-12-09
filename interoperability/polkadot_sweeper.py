import os
import sys
import time
import logging
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class PolkadotSweeper:
    """
    Polkadot/Substrate Account Sweeper.
    
    Designed to empty an account completely by calculating the precise 
    transferable amount (Balance - Fees) and executing a 'transfer_allow_death' 
    call, which allows the account to be reaped (deleted) from the state.
    """

    def __init__(self):
        # Configuration
        self.node_url = os.getenv("POLKADOT_RPC_URL", "wss://rpc.polkadot.io")
        self.mnemonic = os.getenv("POLKADOT_MNEMONIC")
        self.dest_address = os.getenv("POLKADOT_DEST_ADDRESS")
        
        # 1 DOT = 10^10 Plancks
        self.decimals = 10**10

        if not all([self.mnemonic, self.dest_address]):
            logging.critical("Missing Polkadot credentials in .env")
            sys.exit(1)

        # Initialize Connection
        try:
            self.substrate = SubstrateInterface(
                url=self.node_url,
                ss58_format=0, # 0 = Polkadot Mainnet
                type_registry_preset='polkadot'
            )
            logging.info(f"Connected to node: {self.node_url}")
        except Exception as e:
            logging.critical(f"Connection failed: {e}")
            sys.exit(1)

        # Initialize Keypair
        try:
            self.keypair = Keypair.create_from_mnemonic(self.mnemonic, ss58_format=0)
            logging.info(f"Loaded Account: {self.keypair.ss58_address}")
        except Exception as e:
            logging.critical(f"Invalid Mnemonic: {e}")
            sys.exit(1)

    def get_free_balance(self) -> int:
        """Fetches the free balance in Plancks."""
        result = self.substrate.query(
            module='System',
            storage_function='Account',
            params=[self.keypair.ss58_address]
        )
        return int(result.value['data']['free'])

    def sweep(self):
        """
        Executes the sweep logic:
        1. Get Balance
        2. Estimate Fee
        3. Send (Balance - Fee) using transfer_allow_death
        """
        logging.info("Starting sweep process...")
        
        # 1. Get Balance
        free_balance = self.get_free_balance()
        if free_balance == 0:
            logging.warning("Account is already empty.")
            return

        logging.info(f"Current Balance: {free_balance / self.decimals:.4f} DOT")

        # 2. Estimate Fee
        # We construct a dummy call to 'transfer_allow_death' to get precise fee info
        # 'transfer_allow_death' is required to empty an account below ED (1 DOT)
        call_dummy = self.substrate.compose_call(
            call_module='Balances',
            call_function='transfer_allow_death',
            call_params={
                'dest': self.dest_address,
                'value': free_balance # Use full balance for worst-case fee estimation
            }
        )
        
        payment_info = self.substrate.get_payment_info(call=call_dummy, keypair=self.keypair)
        fee = int(payment_info['partialFee'])
        
        logging.info(f"Estimated Fee: {fee / self.decimals:.6f} DOT")

        # 3. Calculate Sendable Amount
        amount_to_send = free_balance - fee

        if amount_to_send <= 0:
            logging.error("Balance insufficient to cover fees.")
            return

        logging.info(f"Sweeping {amount_to_send / self.decimals:.4f} DOT to {self.dest_address}...")

        # 4. Execute Transaction
        try:
            call = self.substrate.compose_call(
                call_module='Balances',
                call_function='transfer_allow_death',
                call_params={
                    'dest': self.dest_address,
                    'value': amount_to_send
                }
            )

            extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=self.keypair)
            receipt = self.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

            if receipt.is_success:
                logging.info(f"✅ Sweep Successful! Hash: {receipt.extrinsic_hash}")
                logging.info(f"Block: {receipt.block_hash}")
                logging.info("Account should now be reaped (deleted) from state.")
                sys.exit(0)
            else:
                logging.error(f"❌ Transaction Failed: {receipt.error_message}")

        except SubstrateRequestException as e:
            logging.error(f"RPC Error: {e}")
        except Exception as e:
            logging.error(f"Unexpected Error: {e}")

if __name__ == "__main__":
    bot = PolkadotSweeper()
    try:
        # Simple loop to retry if RPC fails or to monitor for incoming funds
        while True:
            bot.sweep()
            time.sleep(10) # Wait before retrying (if balance was 0)
    except KeyboardInterrupt:
        sys.exit(0)
