# Refactored engine.py to handle both bruteforce and password spraying,
# and to use a progress bar.
import concurrent.futures
import logging
from protocols import ftp
from protocols import ssh
from tqdm import tqdm

# Mapping of supported protocols to their respective login functions.
PROTOCOLS = {
    "ftp": ftp.try_login,
    "ssh": ssh.try_login,
}

class AttackEngine:
    """
    Core class to orchestrate the attack.
    Manages threads, attack modes, and distributes tasks.
    """
    def __init__(self, args, targets, users, passwords):
        """
        Initializes the AttackEngine with parsed arguments and data lists.
        
        Args:
            args: The argparse Namespace object containing all command-line arguments.
            targets: A list of target hosts.
            users: A list of usernames.
            passwords: A list of passwords.
        """
        self.args = args
        self.targets = targets
        self.users = users
        self.passwords = passwords
        self.logger = logging.getLogger("SprayMaster")

    def run(self):
        """
        Main method to execute the attack based on the specified mode.
        """
        login_func = PROTOCOLS.get(self.args.protocol)
        if not login_func:
            self.logger.error(f"Unsupported protocol: {self.args.protocol}")
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            total_tasks = len(self.targets) * len(self.users) * len(self.passwords)
            
            # Use tqdm to display a progress bar for the user.
            with tqdm(total=total_tasks, desc=f"Attacking {self.args.protocol}", unit="tasks") as pbar:
                if self.args.spray:
                    self._run_password_spray(executor, login_func, pbar)
                else:
                    self._run_bruteforce(executor, login_func, pbar)

    def _run_bruteforce(self, executor, login_func, pbar):
        """
        Runs the full bruteforce attack (target:user:password).
        """
        futures = []
        for target in self.targets:
            for user in self.users:
                for password in self.passwords:
                    # Submit the task to the thread pool and add a done callback.
                    future = executor.submit(login_func, target, user, password, self.args)
                    future.add_done_callback(lambda f: pbar.update(1))
                    futures.append(future)

    def _run_password_spray(self, executor, login_func, pbar):
        """
        Runs the password spraying attack (password:target:user).
        """
        futures = []
        for password in self.passwords:
            for target in self.targets:
                for user in self.users:
                    # Submit the task to the thread pool and add a done callback.
                    future = executor.submit(login_func, target, user, password, self.args)
                    future.add_done_callback(lambda f: pbar.update(1))
                    futures.append(future)
