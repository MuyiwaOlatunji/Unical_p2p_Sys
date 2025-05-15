import asyncio
from p2p_network import P2PNode
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

async def run():
    node = P2PNode("bootstrap", 8468)
    try:
        await node.start()
        logging.info("Bootstrap node running on 127.0.0.1:8468")
        await asyncio.Event().wait()
    except Exception as e:
        logging.error(f"Failed to start bootstrap node: {str(e)}", exc_info=True)
        raise
    finally:
        await node.stop()
        logging.info("Bootstrap node stopped")

if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logging.info("Bootstrap node stopped by user")
    except Exception as e:
        logging.error(f"Error running bootstrap node: {str(e)}", exc_info=True)