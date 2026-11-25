"""Separate worker process, restarted by Docker. No fake proof results."""
import time, logging
from app import STORE
from proof_queue import run_one
if __name__=='__main__':
    logging.basicConfig(level=logging.INFO)
    while True:
        try:
            if not run_one(STORE):time.sleep(15)
        except Exception:
            logging.error('Proof worker failed; retrying without logging evidence or credentials')
            time.sleep(60)
