import asyncio
from p2p_network import P2PNode
from security import generate_key_pair, decrypt_file, compute_file_hash
import logging

async def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    private_key1, public_key1 = generate_key_pair()
    private_key2, public_key2 = generate_key_pair()
    
    # Start bootstrap node
    bootstrap_node = P2PNode("bootstrap", 8468)
    bootstrap_address = await bootstrap_node.start()
    
    # Start nodes
    node1 = P2PNode("student1", 9000, bootstrap_nodes=[('127.0.0.1', 8468)])
    node2 = P2PNode("student2", 9001, bootstrap_nodes=[('127.0.0.1', 8468)])
    addr1 = await node1.start()
    addr2 = await node2.start()
    
    # Test file sharing
    file_data = b"Test document content"
    filename = "test.pdf"
    file_hash = await node1.share_file(filename, file_data, "Documents")
    
    # Test file retrieval
    encrypted_data, aes_key, retrieved_hash = await node2.request_file(None, filename, private_key2, file_hash=file_hash)
    if encrypted_data and aes_key and retrieved_hash:
        decrypted_data = decrypt_file(encrypted_data, aes_key)
        assert decrypted_data == file_data, "Decrypted data does not match original"
        assert compute_file_hash(decrypted_data) == file_hash, "File hash mismatch"
        print("File shared and retrieved successfully")
    else:
        print("File retrieval failed")
    
    # Test multiple files
    file_data2 = b"Another test file"
    filename2 = "test2.txt"
    file_hash2 = await node1.share_file(filename2, file_data2, "Documents")
    encrypted_data2, aes_key2, retrieved_hash2 = await node2.request_file(None, filename2, private_key2, file_hash=file_hash2)
    if encrypted_data2 and aes_key2 and retrieved_hash2:
        decrypted_data2 = decrypt_file(encrypted_data2, aes_key2)
        assert decrypted_data2 == file_data2, "Second file decryption failed"
        assert compute_file_hash(decrypted_data2) == file_hash2, "Second file hash mismatch"
        print("Second file test passed")
    else:
        print("Second file retrieval failed")
    
    # Stop nodes
    await node1.stop()
    await node2.stop()
    await bootstrap_node.stop()

if __name__ == '__main__':
    asyncio.run(main())