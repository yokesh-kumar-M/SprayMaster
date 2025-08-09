# SprayMaster

Multi-protocol password spraying & cracking tool.  
Phase 1 supports FTP with multi-threading and spray mode.

## Usage
```bash
# Spray one password across many users/targets
python -m spraymaster -U users.txt -P passwords.txt -T targets.txt --threads 10 --protocol ftp --spray

# Brute force all combinations on a single target
python -m spraymaster -U users.txt -P passwords.txt -t 127.0.0.1 --threads 5 --protocol ftp
