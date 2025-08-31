import concurrent.futures
from protocols import ftp

PROTOCOLS = {
    "ftp": ftp.try_login,
}

class AttackEngine:
    def __init__(self, protocol, targets, users, passwords, threads=4, spray=False):
        self.protocol = protocol
        self.targets = targets
        self.users = users
        self.passwords = passwords
        self.threads = threads
        self.spray = spray

    def run(self):
        login_func = PROTOCOLS.get(self.protocol)
        if not login_func:
            raise ValueError(f"Unsupported protocol: {self.protocol}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for target in self.targets:
                for user in self.users:
                    for password in self.passwords:
                        executor.submit(login_func, target, user, password)
