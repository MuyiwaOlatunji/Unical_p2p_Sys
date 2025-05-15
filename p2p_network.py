import hashlib
import asyncio
import logging
from kademlia.network import Server
from kademlia.protocol import KademliaProtocol
from security import encrypt_file, decrypt_file, compute_file_hash

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class P2PNode:
    def __init__(self, username, port, bootstrap_nodes=None):
        self.username = username
        self.port = port
        self.bootstrap_nodes = bootstrap_nodes or [('127.0.0.1', 8468)]
        self.files = {}  # filename -> (encrypted_data, category, aes_key, file_hash)
        self.server = Server()
        self.is_running = False

    async def listen(self, port):
        """Custom listen method to initialize protocol and create UDP transport."""
        try:
            loop = asyncio.get_event_loop()
            # Initialize Kademlia protocol with node, storage, and ksize
            self.server.protocol = KademliaProtocol(self.server.node, self.server.storage, ksize=20)
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: self.server.protocol,
                local_addr=('0.0.0.0', port)
            )
            self.server.transport = transport
            self.server.protocol = protocol
            self.is_running = True
            logging.info(f"Node {self.username} listening on 0.0.0.0:{port}, node_id: {self.server.node.id}")
        except Exception as e:
            logging.error(f"Failed to listen on port {port}: {str(e)}", exc_info=True)
            raise

    async def start(self):
        """Start the Kademlia node asynchronously."""
        try:
            await self.listen(self.port)
            if self.bootstrap_nodes:
                bootstrap_result = await self.server.bootstrap(self.bootstrap_nodes)
                if not bootstrap_result:
                    logging.warning(f"No bootstrap nodes contacted for {self.username}")
            address = f"127.0.0.1:{self.port}"
            logging.info(f"Kademlia node started for {self.username} on port {self.port}, node_id: {self.server.node.id}")
            return address
        except Exception as e:
            logging.error(f"Failed to start node for {self.username} on port {self.port}: {str(e)}", exc_info=True)
            raise

    async def stop(self):
        """Stop the Kademlia node asynchronously."""
        if self.is_running:
            self.server.stop()
            if hasattr(self.server, 'transport') and self.server.transport:
                self.server.transport.close()
            self.is_running = False
            logging.info(f"Kademlia node stopped for {self.username}")

    async def share_file(self, filename, file_data, category):
        """Share a file by storing it in the Kademlia DHT."""
        try:
            encrypted_data, aes_key = encrypt_file(file_data)
            file_hash = compute_file_hash(file_data)
            self.files = {}  # filename -> (encrypted_data, category, aes_key, file_hash)
            self.files[filename] = (encrypted_data, category, aes_key, file_hash)
            await self.server.set(file_hash, encrypted_data)
            logging.info(f"File {filename} shared by {self.username} in category {category} with hash {file_hash}")
            return file_hash
        except Exception as e:
            logging.error(f"Failed to share file {filename}: {str(e)}")
            raise

    async def request_file(self, target_address, filename, private_key):
        """Request a file from the Kademlia DHT using its hash."""
        try:
            file_info = self.files.get(filename)
            file_hash = file_info[3] if file_info else None
            if not file_hash:
                logging.warning(f"File {filename} not in local files for {self.username}, attempting DHT lookup")
                return None, None, None  # Need file_hash from database
            encrypted_data = await self.server.get(file_hash)
            if encrypted_data:
                aes_key = file_info[2] if file_info else None
                if not aes_key:
                    logging.error(f"No AES key for {filename}")
                    return None, None, None
                logging.debug(f"Retrieved {filename} from DHT with hash {file_hash}")
                return encrypted_data, aes_key, compute_file_hash(encrypted_data)
            logging.error(f"File {filename} not found in DHT")
            return None, None, None
        except Exception as e:
            logging.error(f"Failed to request file {filename}: {str(e)}")
            return None, None, None