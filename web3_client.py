import json
import os
from typing import Optional, Dict, Any, Literal
from pathlib import Path

from web3 import Web3
from dotenv import load_dotenv

# Load environment variables
env_path = os.path.join(os.path.dirname(__file__), ".env")
print(f"Loading .env from {env_path}")
load_dotenv(env_path, override=True)

# Multi-chain configuration
NETWORKS = {
    'ethereum': {
        'sepolia': {
            'rpc_url': os.getenv("SEPOLIA_RPC_URL"),
            'chain_id': 11155111,
            'name': 'Sepolia Testnet'
        },
        'mainnet': {
            'rpc_url': os.getenv("ETHEREUM_RPC_URL"),
            'chain_id': 1,
            'name': 'Ethereum Mainnet'
        }
    },
    'bsc': {
        'testnet': {
            'rpc_url': os.getenv("BSC_TESTNET_RPC_URL", "https://data-seed-prebsc-1-s1.binance.org:8545/"),
            'chain_id': 97,
            'name': 'BSC Testnet'
        },
        'mainnet': {
            'rpc_url': os.getenv("BSC_MAINNET_RPC_URL", "https://bsc-dataseed1.binance.org/"),
            'chain_id': 56,
            'name': 'BSC Mainnet'
        }
    }
}

# Default network (configurable via env)
DEFAULT_NETWORK = os.getenv("DEFAULT_NETWORK", "ethereum")
DEFAULT_ENV = os.getenv("DEFAULT_ENV", "sepolia")  # or 'testnet' for BSC

PRIVATE_KEY = os.getenv("PRIVATE_KEY")

if not PRIVATE_KEY:
    print("Warning: PRIVATE_KEY not set in .env")

DEPLOYMENTS_DIR = Path(__file__).parent.parent / "deployments"


class MultiChainWeb3Client:
    """Multi-chain Web3 client supporting Ethereum and BSC."""
    
    def __init__(self, network: str = DEFAULT_NETWORK, env: str = DEFAULT_ENV):
        """
        Initialize Web3 client for specific network.
        
        Args:
            network: 'ethereum' or 'bsc'
            env: 'testnet', 'mainnet', 'sepolia'
        """
        self.network = network
        self.env = env
        
        config = NETWORKS.get(network, {}).get(env)
        if not config:
            raise ValueError(f"Invalid network configuration: {network}/{env}")
        
        self.rpc_url = config['rpc_url']
        self.chain_id = config['chain_id']
        self.network_name = config['name']
        
        if not self.rpc_url:
            raise ValueError(f"RPC URL not configured for {network}/{env}")
        
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        if PRIVATE_KEY:
            self.account = self.w3.eth.account.from_key(PRIVATE_KEY)
        else:
            self.account = None
        
        self.contracts: Dict[str, Any] = {}
        self._load_contracts()
    
    def _load_contracts(self):
        """Load contracts for current network."""
        deployments_file = DEPLOYMENTS_DIR / f"{self.network}_{self.env}.json"
        
        # Fallback to sepolia.json for backward compatibility
        if not deployments_file.exists():
            deployments_file = DEPLOYMENTS_DIR / "sepolia.json"
        
        if not deployments_file.exists():
            print(f"Deployments file not found: {deployments_file}")
            return
        
        try:
            with open(deployments_file, "r") as f:
                data = json.load(f)
            
            contract_data = data.get("contracts", data)
            
            for name, info in contract_data.items():
                self.contracts[name] = self.w3.eth.contract(
                    address=info["address"],
                    abi=info["abi"]
                )
            print(f"Loaded {len(self.contracts)} contracts for {self.network_name}")
        except Exception as e:
            print(f"Error loading contracts: {e}")
    
    def send_transaction(self, func, value=0, gas=2000000):
        """
        Send transaction on current network.
        
        Args:
            func: Contract function to execute
            value: Amount in ETH/BNB
            gas: Gas limit
        """
        if not self.account:
            raise Exception("Server wallet not configured (missing PRIVATE_KEY)")
        
        try:
            nonce = self.w3.eth.get_transaction_count(self.account.address)
            
            tx_params = {
                'chainId': self.chain_id,
                'gas': gas,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': nonce,
                'value': self.w3.to_wei(value, 'ether'),
                'from': self.account.address
            }
            
            tx = func.build_transaction(tx_params)
            signed_tx = self.w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                "tx_hash": tx_hash.hex(),
                "status": receipt.status,
                "network": self.network_name,
                "chain_id": self.chain_id
            }
        except Exception as e:
            print(f"Transaction Error on {self.network_name}: {e}")
            raise
    
    def get_balance(self, address: str) -> str:
        """Get balance for address on current network."""
        balance_wei = self.w3.eth.get_balance(address)
        return str(self.w3.from_wei(balance_wei, 'ether'))


# Singleton instances (one per network)
_clients: Dict[str, MultiChainWeb3Client] = {}

def get_web3_client(network: str = DEFAULT_NETWORK, env: str = DEFAULT_ENV) -> MultiChainWeb3Client:
    """Get or create Web3 client for network."""
    key = f"{network}_{env}"
    if key not in _clients:
        _clients[key] = MultiChainWeb3Client(network, env)
    return _clients[key]


# Default client (backward compatibility)
w3_client = get_web3_client()
w3 = w3_client.w3
account = w3_client.account
contracts = w3_client.contracts

def load_contracts():
    """Load contracts for default client."""
    w3_client._load_contracts()

def send_transaction(func, value=0):
    """Send transaction using default client."""
    return w3_client.send_transaction(func, value)
