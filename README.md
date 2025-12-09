# Multi-Chain Automation & Interoperability Toolkit 🌐

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Web3](https://img.shields.io/badge/Web3-EVM%20%7C%20Cosmos%20%7C%20Substrate-orange)
![Security](https://img.shields.io/badge/Focus-Security%20%26%20MEV-red)

A production-grade collection of Python scripts designed for advanced interaction, security, and automation across multiple blockchain architectures.

This toolkit goes beyond standard RPC calls, implementing low-level transaction signing, hybrid Web2/Web3 authentication, and cross-chain interoperability mechanisms.

## 📂 Architecture & Modules

### 1. 🛡️ Security & Mempool Defense
*Located in `/security`*
* **Defensive Front-Runner:** Real-time mempool monitoring via WebSocket. Detects malicious transactions targeting specific wallets and automatically broadcasts a defensive cancellation transaction (higher gas price) to prevent hacks or unauthorized drains.

### 2. 💧 Advanced DeFi & Liquidity
*Located in `/liquidity`*
* **Monad Token Swapper (EIP-2612):** Implements **Gasless Approvals (Permit)** with offline signing (EIP-712). Features a fallback mechanism to standard `approve` if the token lacks permit support.
* **Ronin Validator Exit:** Automated unstaking bot that monitors validator epochs using `estimateGas` polling and sweeps funds to a cold wallet immediately upon release.
* **Pharos Liquidity Provider:** EIP-1559 compatible script for managing liquidity pools with pre-flight simulation (`eth_call`) and reverting error decoding.

### 3. ⚡ MEV & Block Strategies
*Located in `/mev_strategies`*
* **Chiliz Time-Locked Sniper:** A block-synchronized bot that monitors chain height to execute claims exactly at a specific block number. Uses state-change detection (balance monitoring) to ensure execution success.

### 4. 🔗 Interoperability (Non-EVM)
*Located in `/interoperability`*
* **Cosmos (ATOM) Protobuf Signer:** Bypasses high-level CLI tools to construct, serialize, and sign transactions using **Google Protobuf** and `secp256k1` primitives directly.
* **Polkadot (DOT) Sweeper:** Interacts with the Substrate runtime to calculate precise fees and execute `transfer_allow_death`, allowing for complete account reaping (cleaning dust).

### 5. 🤖 Hybrid Interaction (Reverse Engineering)
*Located in `/interaction`*
* **Hybrid Minter Bot:** Demonstrates a Web2/Web3 bridge. Authenticates via JWT with a centralized API, retrieves a server-side cryptographic signature, and constructs a raw EVM transaction (bypassing ABI) to mint assets on-chain.

---

## 🛠️ Technical Highlights

* **Raw Transaction Construction:** Manual encoding of calldata and RLP serialization without relying on full contract ABIs.
* **Gas Optimization:** Dynamic fee estimation supporting both Legacy and EIP-1559 standards.
* **Cryptography:** Implementation of EIP-712 (Typed Data) and Protobuf serialization.
* **Concurrency:** Usage of `threading` and `asyncio` patterns for high-frequency polling.
* **Safety:** Pre-flight simulations and strict nonce management to prevent stuck transactions.

## ⚙️ Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/defi-automation-toolkit.git](https://github.com/YOUR_USERNAME/defi-automation-toolkit.git)
    cd defi-automation-toolkit
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Environment Configuration:**
    Copy the example file and fill in your credentials (RPCs, Private Keys, API Tokens).
    ```bash
    cp .env.example .env
    ```

## ⚠️ Disclaimer

These scripts involve direct interaction with private keys and financial assets. They are provided for educational and portfolio demonstration purposes. **Use at your own risk.** Always test on Testnets (Monad Testnet, Pharos Testnet, etc.) before deploying to Mainnet.
