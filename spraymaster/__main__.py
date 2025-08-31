# Refactored __main__.py to handle argument parsing and tool logic more cleanly.
import argparse
import logging
from core.engine import AttackEngine
from core.utils import load_list

def main():
    """
    Main entry point for SprayMaster.
    Handles argument parsing, logging setup, and orchestrates the attack.
    """
    # Configure logging to display a timestamp, log level, and message.
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO
    )
    
    # Create a custom logger for the application to handle verbosity.
    logger = logging.getLogger("SprayMaster")

    # Set up command-line argument parser.
    parser = argparse.ArgumentParser(
        description="""
        SprayMaster - A powerful, multi-protocol password bruteforcing and spraying tool.
        
        Examples:
          Bruteforce FTP with a userlist and a password list:
          python3 __main__.py -T targets.txt -U users.txt -P passwords.txt -p ftp
          
          Password spray SSH with one password against a user list:
          python3 __main__.py -t 192.168.1.100 -U users.txt -p 'spring2024!' -p ssh --spray
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Argument definitions for targets, users, and passwords.
    parser.add_argument("-u", "--user", help="Single username.")
    parser.add_argument("-U", "--userlist", help="File containing a list of usernames.")
    parser.add_argument("-p", "--password", help="Single password.")
    parser.add_argument("-P", "--passlist", help="File containing a list of passwords.")
    parser.add_argument("-t", "--target", help="Single target host (IP address or hostname).")
    parser.add_argument("-T", "--targetlist", help="File containing a list of target hosts.")

    # Argument definitions for attack configuration.
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5).")
    parser.add_argument("--spray", action="store_true", help="Enable password spraying mode (one password against many users).")
    parser.add_argument("--protocol", choices=["ftp", "ssh"], default="ftp", help="Protocol to attack (choices: ftp, ssh).")
    parser.add_argument("--port", type=int, help="Specify a custom port for the protocol.")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS for protocols that support it.")
    
    # Argument definitions for output control.
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity to show failed login attempts.")

    args = parser.parse_args()

    # Set logging level based on verbosity flag.
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Load lists or use single values based on provided arguments.
    targets = load_list(args.targetlist) if args.targetlist else [args.target]
    users = load_list(args.userlist) if args.userlist else [args.user]
    passwords = load_list(args.passlist) if args.passlist else [args.password]
    
    # Validate that required arguments are provided.
    if not (targets and users and passwords):
        parser.error("You must provide at least one target, one user, and one password.")

    # Initialize and run the attack engine.
    engine = AttackEngine(args, targets, users, passwords)
    engine.run()

if __name__ == "__main__":
    main()
