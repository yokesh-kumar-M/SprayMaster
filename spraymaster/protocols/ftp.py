# Refactored ftp.py to handle SSL and to use better logging.
import ftplib
import logging

def try_login(host, username, password, args):
    """
    Attempts to log in to an FTP server.
    
    Args:
        host (str): The target host.
        username (str): The username to try.
        password (str): The password to try.
        args (argparse.Namespace): The command-line arguments.
    """
    logger = logging.getLogger("SprayMaster")
    port = args.port if args.port else 21
    
    try:
        if args.ssl:
            # Use FTP_TLS for a secure connection if --ssl is specified.
            ftp = ftplib.FTP_TLS()
            ftp.connect(host, port, timeout=10)
            ftp.auth() # Explicit FTPS
            ftp.prot_p() # Set protection level to private
        else:
            # Use standard FTP for an unencrypted connection.
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=10)
            
        ftp.login(username, password)
        logger.info(f"[SUCCESS] {host}:{port} | {username}:{password}")
        ftp.quit()
    except ftplib.error_perm:
        logger.debug(f"[FAIL] {host}:{port} | {username}:{password}")
    except Exception as e:
        logger.error(f"[ERROR] {host}:{port} | {username}:{password} -> {e}")
