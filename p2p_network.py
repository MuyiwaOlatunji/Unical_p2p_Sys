import hashlib
import asyncio
import logging
import os
import json
import base64
from kademlia.network import Server
from kademlia.protocol import KademliaProtocol
from security import encrypt_file, decrypt_file, compute_file_hash

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class P2PNode:
    def __init__(self, username, port, address='0.0.0.0', bootstrap_nodes=None):
        self.username = username
        self.port = port
        self.address = address
        self.bootstrap_nodes = bootstrap_nodes or [('127.0.0.1', 8468)]
        self.files = {}  # filename -> (encrypted_data, category, aes_key, file_hash)
        self.server = Server()
        self.is_running = False

    async def listen(self):
        try:
            loop = asyncio.get_event_loop()
            self.server.protocol = KademliaProtocol(self.server.node, self.server.storage, ksize=20)
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: self.server.protocol,
                local_addr=(self.address, self.port)
            )
            self.server.transport = transport
            self.server.protocol = protocol
            self.is_running = True
            logging.info(f"Node {self.username} listening on {self.address}:{self.port}, node_id: {self.server.node.id}")
        except Exception as e:
            logging.error(f"Failed to listen on {self.address}:{self.port}: {str(e)}", exc_info=True)
            raise

    async def start(self):
        try:
            await self.listen()
            if self.bootstrap_nodes:
                bootstrap_result = await self.server.bootstrap(self.bootstrap_nodes)
                if not bootstrap_result:
                    logging.warning(f"No bootstrap nodes contacted for {self.username}")
            address = f"{self.address}:{self.port}"
            logging.info(f"Kademlia node started for {self.username} on port {self.port}, node_id: {self.server.node.id}")
            return address
        except Exception as e:
            logging.error(f"Failed to start node for {self.username} on port {self.port}: {str(e)}", exc_info=True)
            raise

    async def stop(self):
        if self.is_running:
            self.server.stop()
            if hasattr(self.server, 'transport') and self.server.transport:
                self.server.transport.close()
            self.is_running = False
            logging.info(f"Kademlia node stopped for {self.username}")

    async def share_file(self, filename, category, aes_key, save_path):
        try:
            with open(save_path, 'rb') as f:
                encrypted_data = f.read()
            with open(save_path, 'rb') as f:
                decrypted_data = decrypt_file(f.read(), aes_key)
            file_hash = compute_file_hash(decrypted_data)
            metadata = {
                'filename': filename,
                'category': category,
                'aes_key': base64.b64encode(aes_key).decode('utf-8'),
                'location': save_path
            }
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            await self.server.set(file_hash, metadata_bytes)
            logging.debug(f"Stored metadata for {filename} in DHT with hash {file_hash}, metadata: {metadata}")
            self.files[filename] = (encrypted_data, category, aes_key, file_hash)
            logging.info(f"File {filename} shared by {self.username} in category {category} with hash {file_hash}")
            return file_hash
        except Exception as e:
            logging.error(f"Failed to share file {filename}: {str(e)}", exc_info=True)
            raise

    async def request_file(self, target_address, filename, private_key, file_hash):
        logging.debug(f"Requesting file {filename} with file_hash {file_hash} for user {self.username}")
        try:
            if not file_hash:
                logging.error(f"No file_hash provided for {filename}")
                return None, None, None
            file_info = self.files.get(filename)
            if file_info and file_info[3] == file_hash:
                logging.debug(f"Found {filename} in local files for {self.username} with hash {file_hash}")
                return file_info[0], file_info[2], file_info[3]
            metadata_bytes = await self.server.get(file_hash)
            if not metadata_bytes:
                logging.error(f"No metadata found in DHT for file_hash {file_hash} (key: file:{file_hash})")
                return None, None, None
            try:
                metadata = json.loads(metadata_bytes.decode('utf-8'))
                logging.debug(f"Retrieved metadata for {filename}: {metadata}")
                aes_key = base64.b64decode(metadata['aes_key'])
            except (json.JSONDecodeError, ValueError) as e:
                logging.error(f"Failed to deserialize metadata for {filename}: {str(e)}")
                return None, None, None
            if 'location' in metadata:
                try:
                    with open(metadata['location'], 'rb') as f:
                        encrypted_data = f.read()
                    logging.debug(f"Retrieved {filename} from {metadata['location']} with hash {file_hash}")
                    return encrypted_data, aes_key, file_hash
                except FileNotFoundError:
                    logging.error(f"File {filename} not found at {metadata['location']}")
            upload_path = os.path.join('Uploads', filename)
            try:
                with open(upload_path, 'rb') as f:
                    encrypted_data = f.read()
                logging.debug(f"Retrieved {filename} from Uploads directory with hash {file_hash}")
                return encrypted_data, aes_key, file_hash
            except FileNotFoundError:
                logging.error(f"File {filename} not found in Uploads directory at {upload_path}")
                return None, None, None
        except Exception as e:
            logging.error(f"Failed to request file {filename}: {str(e)}", exc_info=True)
            return None, None, None