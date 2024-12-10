
from src.ftp_server.ftp_server import FTPServer
import logging

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logger.info("Starting FTP server...")                          
    server = FTPServer()
    server.start()
