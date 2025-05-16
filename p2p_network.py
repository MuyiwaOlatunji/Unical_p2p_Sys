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
        """Share a file by storing it locally and metadata in the Kademlia DHT."""
        try:
            # Encrypt the file
            encrypted_data, aes_key = encrypt_file(file_data)
            file_hash = compute_file_hash(file_data)

            # Save encrypted file locally
            os.makedirs('Uploads', exist_ok=True)
            upload_path = os.path.join('Uploads', filename)
            with open(upload_path, 'wb') as f:
                f.write(encrypted_data)
            logging.debug(f"Saved encrypted file {filename} to {upload_path}")

            # Prepare metadata (encode aes_key to base64 for JSON compatibility)
            metadata = {
                'filename': filename,
                'category': category,
                'aes_key': base64.b64encode(aes_key).decode('utf-8') if isinstance(aes_key, bytes) else aes_key,
                'location': upload_path
            }
            # Serialize metadata to JSON bytes
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            await self.server.set(file_hash, metadata_bytes)
            logging.debug(f"Stored metadata for {filename} in DHT with hash {file_hash}, metadata: {metadata}")

            # Update files dictionary (do not reset)
            self.files[filename] = (encrypted_data, category, aes_key, file_hash)
            logging.info(f"File {filename} shared by {self.username} in category {category} with hash {file_hash}")
            return file_hash
        except Exception as e:
            logging.error(f"Failed to share file {filename}: {str(e)}")
            raise

    async def request_file(self, target_address, filename, private_key):
        """Request a file using its hash, retrieving metadata from DHT and file from local storage."""
        try:
            file_info = self.files.get(filename)
            file_hash = file_info[3] if file_info else None
            if not file_hash:
                logging.warning(f"File {filename} not in local files for {self.username}, attempting DHT lookup")
                return None, None, None  # Need file_hash from database

            # Retrieve metadata from DHT
            metadata_bytes = await self.server.get(file_hash)
            if metadata_bytes:
                # Deserialize metadata
                try:
                    metadata = json.loads(metadata_bytes.decode('utf-8'))
                    # Decode aes_key from base64
                    aes_key = base64.b64decode(metadata['aes_key']) if 'aes_key' in metadata else None
                except (json.JSONDecodeError, ValueError) as e:
                    logging.error(f"Failed to deserialize metadata for {filename}: {str(e)}")
                    return None, None, None

                # Load file from local storage
                if 'location' in metadata:
                    try:
                        with open(metadata['location'], 'rb') as f:
                            encrypted_data = f.read()
                        logging.debug(f"Retrieved {filename} from {metadata['location']} with hash {file_hash}")
                        return encrypted_data, aes_key, file_hash
                    except FileNotFoundError:
                        logging.error(f"File {filename} not found at {metadata['location']}")
                else:
                    logging.warning(f"No location in metadata for {filename}")

            # Fallback to local Uploads directory
            upload_path = os.path.join('Uploads', filename)
            try:
                with open(upload_path, 'rb') as f:
                    encrypted_data = f.read()
                aes_key = file_info[2] if file_info else None
                if not aes_key:
                    logging.error(f"No AES key for {filename}")
                    return None, None, None
                logging.debug(f"Retrieved {filename} from Uploads directory with hash {file_hash}")
                return encrypted_data, aes_key, file_hash
            except FileNotFoundError:
                logging.error(f"File {filename} not found in Uploads")
                return None, None, None
        except Exception as e:
            logging.error(f"Failed to request file {filename}: {str(e)}")
            return None, None, None