# FTP Brute Force Login Script

A Python script that performs a brute-force attack on FTP servers using the `rockyou.txt` wordlist. The script automatically detects the local machine's IP address as the FTP server and attempts to log in with a given username and multiple passwords from the wordlist. The script connects on port 21, the default FTP port.

## Features:
- **Automatic Server Detection**: The script detects the local machine’s IP address as the FTP server.
- **Wordlist-based Brute Force**: Uses `rockyou.txt` for password attempts.
- **Port 21 Support**: Connects to FTP on port 21, the default FTP port.
- **Error Handling**: Provides feedback on success or failure for each password attempt.

## Requirements:
- Python 3.x
- `rockyou.txt` (password list)
  - You can download the wordlist from various sources online or use the one available in Kali Linux under `/usr/share/wordlists/rockyou.txt`.

## How to Use:

1. **Download or Prepare `rockyou.txt`:**
   - Ensure that `rockyou.txt` is in the same directory as this script.
   - If you don’t have the wordlist, download it or use the default one from Kali Linux.

2. **Clone or Download the Script:**
   - Clone the repository or download the script to your local machine.

3. **Run the Script:**
   - Open a terminal and navigate to the directory where the script is located.
   - Run the script using the following command:
     ```bash
     python3 ftp_bruteforce.py
     ```

4. **Input FTP Details:**
   - Enter the **username** when prompted.
   - The script will attempt to brute force the password using `rockyou.txt`.

## Disclaimer:
This script is for **educational purposes only** and should only be used with permission for **ethical penetration testing**. **Unauthorized access** to systems is illegal.

## License:
This project is licensed under the MIT License.
