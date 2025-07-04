# utils.py

import logging
import os

LOG_FILE = "audit.log"

def setup_logger():
    """Configure le logger global pour écrire dans audit.log"""
    os.makedirs("audits", exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        filemode="a",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )

def log_info(message):
    """Log d'information"""
    logging.info(message)

def log_error(message):
    """Log d'erreur"""
    logging.error(message)
