import os
import sys
import time
import base64
import hashlib
import json
import logging
import requests
import ecdsa
from typing import Any, Tuple
from dotenv import load_dotenv

# Protobuf & Cosmos Imports
# Note: Requires 'cosmospy-protobuf' library
from google.protobuf.any_pb2 import Any as PbAny
from cosmospy_protobuf.cosmos.tx.v1beta1 import tx_pb2
from cosmospy_protobuf.cosmos.tx.signing.v1beta1 import signing_pb2
from cosmospy_protobuf.cosmos.crypto.secp256k1 import keys_pb2
from cosmospy_protobuf.cosmos.base.v1beta1 import coin_pb2
from cosmospy_protobuf.cosmos.bank.v1beta1 import tx_pb2 as bank_tx_pb2
from cosmospy._wallet import privkey_to_address, privkey_to_pubkey

# Load environment variables
load_dotenv()

# Configure Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class CosmosTxBuilder:
    """
    Low-level Transaction Builder for Cosmos SDK Chains.
    
    Demonstrates manual Protobuf serialization and signing, bypassing 
    high-level CLI wrappers to interact directly with the blockchain core.
    """
    
    def __init__(
        self,
        privkey: bytes,
        account_num: int,
        sequence: int,
        fee: int,
        gas: int,
        chain_id: str,
        hrp: str = "cosmos",
        fee_denom: str = "uatom",
        memo: str = ""
    ):
        self._privkey = privkey
        self._account_num = account_num
        self._sequence = sequence
        self._fee = fee
        self._gas = gas
        self._chain_id = chain_id
        self._hrp = hrp
        self._fee_denom = fee_denom
        self._memo = memo
        self._msgs: list[dict] = []

    def add_transfer(self, recipient: str, amount: int, denom: str = "uatom") -> None:
        """Adds a MsgSend instruction to the transaction bundle."""
        transfer = {
            "type": "cosmos-sdk/MsgSend",
            "value": {
                "from_address": privkey_to_address(self._privkey, hrp=self._hrp),
                "to_address": recipient,
                "amount": [{"denom": denom, "amount": str(amount)}],
            },
        }
        self._msgs.append(transfer)

    def get_signed_tx_bytes(self) -> bytes:
        """
        Constructs the canonical SignDoc, signs it using secp256k1, 
        and packages the final Protobuf TxRaw.
        """
        # 1. Build TxBody (The content)
        tx_body = tx_pb2.TxBody()
        for msg in self._msgs:
            if msg["type"] == "cosmos-sdk/MsgSend":
                val = msg["value"]
                msg_send = bank_tx_pb2.MsgSend()
                msg_send.from_address = val["from_address"]
                msg_send.to_address = val["to_address"]
                
                coin_obj = msg_send.amount.add()
                coin_obj.denom = val["amount"][0]["denom"]
                coin_obj.amount = val["amount"][0]["amount"]
                
                # Pack into Any for Protobuf polymorphism
                any_msg = PbAny()
                any_msg.Pack(msg_send)
                any_msg.type_url = "/cosmos.bank.v1beta1.MsgSend"
                tx_body.messages.append(any_msg)
            else:
                raise ValueError(f"Unsupported message type: {msg['type']}")
        
        tx_body.memo = self._memo
        tx_body.timeout_height = 0

        # 2. Build AuthInfo (Signer details & Fees)
        signer_info = tx_pb2.SignerInfo()
        pubkey_proto = keys_pb2.PubKey()
        pubkey_proto.key = privkey_to_pubkey(self._privkey)
        
        pubkey_any = PbAny()
        pubkey_any.Pack(pubkey_proto)
        pubkey_any.type_url = "/cosmos.crypto.secp256k1.PubKey"
        
        signer_info.public_key.CopyFrom(pubkey_any)
        signer_info.sequence = self._sequence
        signer_info.mode_info.single.mode = signing_pb2.SignMode.SIGN_MODE_DIRECT

        auth_info = tx_pb2.AuthInfo()
        auth_info.signer_infos.append(signer_info)
        
        fee_proto = tx_pb2.Fee()
        fee_proto.gas_limit = self._gas
        coin_fee = coin_pb2.Coin()
        coin_fee.denom = self._fee_denom
        coin_fee.amount = str(self._fee)
        fee_proto.amount.append(coin_fee)
        auth_info.fee.CopyFrom(fee_proto)

        # 3. Create Canonical SignDoc (What actually gets signed)
        sign_doc = tx_pb2.SignDoc(
            body_bytes=tx_body.SerializeToString(),
            auth_info_bytes=auth_info.SerializeToString(),
            chain_id=self._chain_id,
            account_number=self._account_num,
        )

        # 4. Sign Deterministically (ECDSA/SHA256)
        sk = ecdsa.SigningKey.from_string(self._privkey, curve=ecdsa.SECP256k1)
        signature = sk.sign_deterministic(
            sign_doc.SerializeToString(),
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string_canonize,
        )

        # 5. Assemble Final Tx
        tx_final = tx_pb2.Tx()
        tx_final.body.CopyFrom(tx_body)
        tx_final.auth_info.CopyFrom(auth_info)
        tx_final.signatures.append(signature)

        return tx_final.SerializeToString()

class CosmosAutoSender:
    def __init__(self):
        # Configuration from Environment
        self.lcd_url = os.getenv("COSMOS_LCD_URL", "https://cosmoshub.lava.build:443")
        self.chain_id = os.getenv("COSMOS_CHAIN_ID", "cosmoshub-4")
        self.private_key_hex = os.getenv("COSMOS_PRIVATE_KEY")
        self.dest_address = os.getenv("COSMOS_DEST_ADDRESS")
        self.sender_address = os.getenv("COSMOS_SENDER_ADDRESS")
        
        # Operational Config
        self.denom = "uatom"
        self.threshold = int(os.getenv("COSMOS_THRESHOLD_UATOM", 30000))
        self.gas_limit = 160000
        self.gas_price_atom = 0.0055

        if not all([self.private_key_hex, self.dest_address, self.sender_address]):
            logging.critical("Missing Cosmos credentials in .env")
            sys.exit(1)

    def _get_account_info(self) -> Tuple[int, int]:
        """Fetches Account Number and Sequence from LCD (REST API)."""
        uri = f"{self.lcd_url}/cosmos/auth/v1beta1/accounts/{self.sender_address}"
        try:
            resp = requests.get(uri, timeout=10)
            resp.raise_for_status()
            data = resp.json().get('account', {})
            # Handle wrapping for vesting accounts if necessary
            base = data.get('base_account', data) if 'base_account' in data else data
            return int(base.get('account_number', 0)), int(base.get('sequence', 0))
        except Exception as e:
            logging.error(f"Failed to fetch account info: {e}")
            raise

    def _get_balance(self) -> int:
        uri = f"{self.lcd_url}/cosmos/bank/v1beta1/balances/{self.sender_address}"
        try:
            resp = requests.get(uri, timeout=10)
            if resp.status_code == 200:
                balances = resp.json().get("balances", [])
                for b in balances:
                    if b["denom"] == self.denom:
                        return int(b["amount"])
            return 0
        except Exception:
            return 0

    def run_monitor(self):
        logging.info(f"Started Cosmos Monitor for {self.sender_address}...")
        
        while True:
            balance = self._get_balance()
            logging.info(f"Current Balance: {balance} {self.denom}")
            
            if balance > self.threshold:
                amount_to_send = balance - self.threshold
                logging.info(f"Threshold exceeded. Preparing to send {amount_to_send} {self.denom}...")
                self._execute_transfer(amount_to_send)
            
            time.sleep(10) # 10s Poll Interval

    def _execute_transfer(self, amount: int):
        try:
            acc_num, seq = self._get_account_info()
            fee_amount = int(self.gas_price_atom * self.gas_limit * 1000000) # Convert ATOM to uATOM logic roughly

            # Initialize Builder
            builder = CosmosTxBuilder(
                privkey=bytes.fromhex(self.private_key_hex),
                account_num=acc_num,
                sequence=seq,
                fee=2000, # Hardcoded safe fee or dynamic calc
                gas=self.gas_limit,
                chain_id=self.chain_id
            )
            
            builder.add_transfer(self.dest_address, amount, self.denom)
            
            # Serialize & Encode
            tx_bytes = builder.get_signed_tx_bytes()
            tx_b64 = base64.b64encode(tx_bytes).decode("utf-8")
            
            # Broadcast via REST
            payload = {
                "tx_bytes": tx_b64,
                "mode": "BROADCAST_MODE_SYNC"
            }
            
            logging.info("Broadcasting Transaction...")
            resp = requests.post(
                f"{self.lcd_url}/cosmos/tx/v1beta1/txs",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            
            res_json = resp.json()
            if res_json.get('tx_response', {}).get('code', -1) == 0:
                tx_hash = res_json['tx_response']['txhash']
                logging.info(f"Success! Hash: {tx_hash}")
            else:
                logging.error(f"Broadcast Failed: {res_json}")

        except Exception as e:
            logging.error(f"Transaction Error: {e}")

if __name__ == "__main__":
    bot = CosmosAutoSender()
    try:
        bot.run_monitor()
    except KeyboardInterrupt:
        sys.exit(0)
