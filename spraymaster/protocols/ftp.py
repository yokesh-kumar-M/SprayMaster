import ftplib
import logging

def try_login(host, username, password):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=5)
        ftp.login(username, password)
        logging.info(f"[SUCCESS] {host} | {username}:{password}")
        ftp.quit()
    except ftplib.error_perm:
        logging.warning(f"[FAIL] {host} | {username}:{password}")
    except Exception as e:
        logging.error(f"[ERROR] {host} | {username}:{password} {e}")
