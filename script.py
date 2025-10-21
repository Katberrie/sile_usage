import os
import time
import logging
from typing import Dict, Any, List, Optional

import requests
from web3 import Web3
from web3.contract import Contract
from web3.exceptions import BlockNotFound

# Basic logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# --- Constants and Configuration ---
# In a real application, these would come from a config file or environment variables
SOURCE_CHAIN_RPC_URL = os.getenv('SOURCE_CHAIN_RPC_URL', 'https://rpc.ankr.com/eth_sepolia')
DESTINATION_CHAIN_RPC_URL = os.getenv('DESTINATION_CHAIN_RPC_URL', 'https://rpc.ankr.com/polygon_mumbai')

# Simplified ABI for the source chain bridge contract
SOURCE_BRIDGE_ABI = '''
[
    {
        "anonymous": false,
        "inputs": [
            {"indexed": true, "name": "sender", "type": "address"},
            {"indexed": true, "name": "recipient", "type": "address"},
            {"indexed": false, "name": "amount", "type": "uint256"},
            {"indexed": false, "name": "destinationChainId", "type": "uint256"},
            {"indexed": true, "name": "nonce", "type": "uint256"}
        ],
        "name": "DepositMade",
        "type": "event"
    }
]
'''
SOURCE_BRIDGE_ADDRESS = '0x9A2b455D57759F997b6324eC9BB9dE8A8641551a' # Example Address

# Simplified ABI for the destination chain bridge contract
DESTINATION_BRIDGE_ABI = '''
[
    {
        "inputs": [
            {"name": "recipient", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "sourceNonce", "type": "uint256"}
        ],
        "name": "mintTokens",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]
'''
DESTINATION_BRIDGE_ADDRESS = '0x5B6a9B55B6C8f7B2bEa7bF1f937B8b9933B02b54' # Example Address

RISK_API_ENDPOINT = 'https://api.example.com/validate-tx' # Dummy API for validation demonstration
POLLING_INTERVAL_SECONDS = 30
BLOCK_PROCESSING_CHUNK_SIZE = 500


class BlockchainConnector:
    """
    Manages the connection to a blockchain node via Web3.
    Handles connection setup and provides a simple interface to get Web3 and Contract instances.
    """
    def __init__(self, rpc_url: str):
        """
        Initializes the connector with a given RPC URL.
        
        Args:
            rpc_url (str): The HTTP RPC endpoint for the blockchain node.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        try:
            self.web3 = Web3(Web3.HTTPProvider(rpc_url))
            if not self.web3.is_connected():
                raise ConnectionError(f"Failed to connect to blockchain node at {rpc_url}")
            self.logger.info(f"Successfully connected to node at {rpc_url}")
        except Exception as e:
            self.logger.error(f"Error initializing Web3 connection: {e}")
            raise

    def get_contract(self, address: str, abi: str) -> Optional[Contract]:
        """
        Creates a Web3 Contract instance.
        
        Args:
            address (str): The contract's address.
            abi (str): The contract's ABI.
            
        Returns:
            Optional[Contract]: A Web3 Contract instance, or None if the address is invalid.
        """
        try:
            checksum_address = self.web3.to_checksum_address(address)
            return self.web3.eth.contract(address=checksum_address, abi=abi)
        except ValueError:
            self.logger.error(f"Invalid address format: {address}")
            return None


class EventScanner:
    """
    Scans a given contract on a source chain for specific events within a block range.
    This class is designed to be resilient to RPC node limitations on query range.
    """
    def __init__(self, connector: BlockchainConnector, contract: Contract, event_name: str):
        """
        Initializes the EventScanner.
        
        Args:
            connector (BlockchainConnector): The connector for the source chain.
            contract (Contract): The Web3 contract instance to scan.
            event_name (str): The name of the event to listen for (e.g., 'DepositMade').
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.web3 = connector.web3
        self.contract = contract
        self.event_name = event_name
        self.event = getattr(self.contract.events, self.event_name, None)
        if not self.event:
            raise ValueError(f"Event '{event_name}' not found in contract ABI.")

    def get_events(self, from_block: int, to_block: int) -> List[Dict[str, Any]]:
        """
        Retrieves events in a given block range, handling large ranges by chunking.
        
        Args:
            from_block (int): The starting block number.
            to_block (int): The ending block number.
            
        Returns:
            List[Dict[str, Any]]: A list of decoded event logs.
        """
        all_events = []
        self.logger.info(f"Scanning for '{self.event_name}' events from block {from_block} to {to_block}.")
        
        for start in range(from_block, to_block + 1, BLOCK_PROCESSING_CHUNK_SIZE):
            end = min(start + BLOCK_PROCESSING_CHUNK_SIZE - 1, to_block)
            try:
                self.logger.debug(f"Querying chunk from block {start} to {end}.")
                event_filter = self.event.create_filter(fromBlock=start, toBlock=end)
                chunk_events = event_filter.get_all_entries()
                if chunk_events:
                    self.logger.info(f"Found {len(chunk_events)} events in blocks {start}-{end}.")
                    all_events.extend(chunk_events)
            except Exception as e:
                self.logger.error(f"Error fetching events in range {start}-{end}: {e}")
                # In a production system, you might retry or handle this more gracefully.
                break
        return [self._format_event(event) for event in all_events]

    @staticmethod
    def _format_event(event: Any) -> Dict[str, Any]:
        """
        Formats a raw Web3 event log into a more usable dictionary.
        """
        return {
            'tx_hash': event.transactionHash.hex(),
            'block_number': event.blockNumber,
            'args': dict(event.args)
        }


class TransactionValidator:
    """
    Performs validation checks on a detected bridge event.
    This is a critical component for security, preventing invalid or malicious transfers.
    """
    def __init__(self, processed_nonces: set, max_amount_wei: int):
        """
        Initializes the validator.

        Args:
            processed_nonces (set): A set of already processed transaction nonces to prevent replays.
            max_amount_wei (int): The maximum allowed transfer amount in Wei.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.processed_nonces = processed_nonces
        self.max_amount_wei = max_amount_wei

    def validate(self, event_data: Dict[str, Any]) -> bool:
        """
        Runs a series of checks on the event data.
        
        Args:
            event_data (Dict[str, Any]): The formatted event data from the EventScanner.
            
        Returns:
            bool: True if the event is valid, False otherwise.
        """
        args = event_data.get('args', {})
        nonce = args.get('nonce')
        amount = args.get('amount')
        recipient = args.get('recipient')

        # 1. Check for replay attacks using a unique nonce
        if nonce is None or nonce in self.processed_nonces:
            self.logger.warning(f"Validation failed for tx {event_data['tx_hash']}: Invalid or replayed nonce {nonce}.")
            return False

        # 2. Check transfer amount limits
        if amount is None or amount <= 0 or amount > self.max_amount_wei:
            self.logger.warning(f"Validation failed for tx {event_data['tx_hash']}: Amount {amount} out of bounds.")
            return False

        # 3. Check for valid recipient address
        if not recipient or not Web3.is_address(recipient):
            self.logger.warning(f"Validation failed for tx {event_data['tx_hash']}: Invalid recipient address {recipient}.")
            return False
        
        # 4. (Simulation) Call an external risk assessment API
        if not self._external_risk_check(event_data):
            self.logger.warning(f"Validation failed for tx {event_data['tx_hash']}: Flagged by external risk API.")
            return False

        self.logger.info(f"Successfully validated event from tx {event_data['tx_hash']} with nonce {nonce}.")
        return True

    def _external_risk_check(self, event_data: Dict[str, Any]) -> bool:
        """
        Simulates a call to an external service for additional validation.
        In a real scenario, this could check against blacklists, etc.
        """
        try:
            # We use a dummy endpoint, so this will likely fail. We'll simulate a successful response.
            # response = requests.post(RISK_API_ENDPOINT, json=event_data, timeout=5)
            # response.raise_for_status()
            # return response.json().get('status') == 'approved'
            self.logger.debug(f"Simulating successful external risk check for tx {event_data['tx_hash']}.")
            return True # Simulate a successful check
        except requests.exceptions.RequestException as e:
            self.logger.error(f"External risk API call failed: {e}. Defaulting to failed validation.")
            return False # Fail-safe: if the API is down, don't approve transactions


class TransactionProcessor:
    """
    Processes a validated event by simulating a transaction on the destination chain.
    """
    def __init__(self, connector: BlockchainConnector, contract: Contract):
        """
        Initializes the processor.
        
        Args:
            connector (BlockchainConnector): The connector for the destination chain.
            contract (Contract): The Web3 contract instance for the destination bridge.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.web3 = connector.web3
        self.contract = contract

    def process(self, event_data: Dict[str, Any]) -> bool:
        """
        Simulates the 'mintTokens' transaction on the destination chain.
        
        Args:
            event_data (Dict[str, Any]): The validated event data.
            
        Returns:
            bool: True if processing was successfully simulated, False otherwise.
        """
        args = event_data['args']
        recipient = args['recipient']
        amount = args['amount']
        source_nonce = args['nonce']
        source_tx_hash = event_data['tx_hash']

        self.logger.info(f"Processing mint for recipient {recipient} with amount {amount} (from source tx {source_tx_hash}).")
        
        try:
            # In a real application, this is where you would build, sign, and send the transaction.
            # This requires a wallet with private key management, nonce management, and gas estimation.
            # For this simulation, we will just log the intended action.
            
            function_call = self.contract.functions.mintTokens(
                recipient,
                amount,
                source_nonce
            )
            
            # Simulate transaction building
            tx_params = {
                'from': '0x...SIGNER_ADDRESS...', # The bridge operator's address
                'nonce': self.web3.eth.get_transaction_count('0x...SIGNER_ADDRESS...'),
                'gas': 200000, # Estimated gas
                'gasPrice': self.web3.eth.gas_price
            }
            # tx = function_call.build_transaction(tx_params)
            # signed_tx = self.web3.eth.account.sign_transaction(tx, private_key='...')
            # tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            self.logger.info(f"[SIMULATION] Would call 'mintTokens' on {self.contract.address} for nonce {source_nonce}.")
            self.logger.info(f"[SIMULATION] Transaction details: to={recipient}, amount={amount}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to simulate transaction for source nonce {source_nonce}: {e}")
            return False


class BridgeOrchestrator:
    """
    The main orchestrator that coordinates the entire process.
    It runs a continuous loop to scan for, validate, and process bridge events.
    """
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.last_scanned_block = self._get_initial_block()
        self.processed_nonces = set() # In-memory store for nonces. A DB would be used in production.
        self.is_running = True
        
        # Initialize components
        self.source_connector = BlockchainConnector(SOURCE_CHAIN_RPC_URL)
        self.dest_connector = BlockchainConnector(DESTINATION_CHAIN_RPC_URL)

        source_contract = self.source_connector.get_contract(SOURCE_BRIDGE_ADDRESS, SOURCE_BRIDGE_ABI)
        dest_contract = self.dest_connector.get_contract(DESTINATION_BRIDGE_ADDRESS, DESTINATION_BRIDGE_ABI)

        if not source_contract or not dest_contract:
            raise RuntimeError("Failed to initialize contracts. Check addresses and ABIs.")

        self.scanner = EventScanner(self.source_connector, source_contract, 'DepositMade')
        # Max amount: 10 ETH (in Wei) for this example
        self.validator = TransactionValidator(self.processed_nonces, max_amount_wei=Web3.to_wei(10, 'ether'))
        self.processor = TransactionProcessor(self.dest_connector, dest_contract)

    def _get_initial_block(self) -> int:
        """
        Determines the starting block for scanning.
        In a real system, this would be loaded from a persistent state store.
        For this simulation, we start from a recent block.
        """
        try:
            # Start scanning from 100 blocks behind the latest to handle reorgs
            latest_block = BlockchainConnector(SOURCE_CHAIN_RPC_URL).web3.eth.block_number
            return max(0, latest_block - 100)
        except Exception as e:
            self.logger.error(f"Could not fetch latest block number: {e}. Starting from block 0.")
            return 0

    def run(self):
        """
        Starts the main orchestration loop.
        """
        self.logger.info(f"Bridge Orchestrator started. Initial scan block: {self.last_scanned_block}")
        while self.is_running:
            try:
                current_block = self.source_connector.web3.eth.block_number
                if current_block > self.last_scanned_block:
                    # Define the range to scan. Add a buffer for block confirmations.
                    scan_to_block = max(self.last_scanned_block, current_block - 6) # 6-block confirmation delay
                    
                    if scan_to_block > self.last_scanned_block:
                        events = self.scanner.get_events(self.last_scanned_block + 1, scan_to_block)
                        
                        for event in events:
                            if self.validator.validate(event):
                                if self.processor.process(event):
                                    # Mark as processed only on successful processing
                                    self.processed_nonces.add(event['args']['nonce'])
                                    self.logger.info(f"Successfully processed event with nonce {event['args']['nonce']}")
                                else:
                                    self.logger.error(f"Failed to process event with nonce {event['args']['nonce']}. Will retry later.")
                        
                        # Update state after a successful batch
                        self.last_scanned_block = scan_to_block
                        self.logger.info(f"Scan complete. Last scanned block is now {self.last_scanned_block}")
                else:
                    self.logger.debug("No new blocks to scan.")

                time.sleep(POLLING_INTERVAL_SECONDS)

            except BlockNotFound:
                self.logger.warning("A block was not found, possibly due to a reorg. Re-evaluating last scanned block.")
                # Simple reorg handling: step back a few blocks
                self.last_scanned_block = max(0, self.last_scanned_block - 10)
                time.sleep(POLLING_INTERVAL_SECONDS)
            except KeyboardInterrupt:
                self.logger.info("Shutdown signal received. Exiting...")
                self.is_running = False
            except Exception as e:
                self.logger.critical(f"An unexpected error occurred in the main loop: {e}")
                time.sleep(POLLING_INTERVAL_SECONDS * 2) # Longer sleep on critical error


if __name__ == "__main__":
    print("Starting the Cross-Chain Bridge Event Listener Simulation.")
    print("This script will poll for 'DepositMade' events on the source chain...")
    print("Press Ctrl+C to stop.")
    
    # It's recommended to set RPC URLs via environment variables:
    # export SOURCE_CHAIN_RPC_URL='https://your_sepolia_rpc_url'
    # export DESTINATION_CHAIN_RPC_URL='https://your_mumbai_rpc_url'

    try:
        orchestrator = BridgeOrchestrator()
        orchestrator.run()
    except (ConnectionError, RuntimeError) as e:
        logging.critical(f"Failed to start the orchestrator: {e}")

# @-internal-utility-start
def validate_payload_9124(payload: dict):
    """Validates incoming data payload on 2025-10-21 19:35:24"""
    if not isinstance(payload, dict):
        return False
    required_keys = ['id', 'timestamp', 'data']
    return all(key in payload for key in required_keys)
# @-internal-utility-end


# @-internal-utility-start
CACHE = {}
def get_from_cache_6427(key: str):
    """Retrieves an item from cache. Implemented on 2025-10-21 19:35:57"""
    return CACHE.get(key, None)
# @-internal-utility-end


# @-internal-utility-start
CACHE = {}
def get_from_cache_3593(key: str):
    """Retrieves an item from cache. Implemented on 2025-10-21 19:37:22"""
    return CACHE.get(key, None)
# @-internal-utility-end

