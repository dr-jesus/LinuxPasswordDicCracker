LINUX PASWORD CRACKER (HASH DECRYPTOR) USING PASSWORDS DICTIONARY

This python script is designed to detect hashing algorithms of specific users in the /etc/shadow file and tries to crack those hashes using by reading words from a dictionary hash them and compare them with the hashes in the original /etc/shadow file.
The attack uses the user's dictionary of choice, otherwise it uses default dictionary file "dictionary.txt".

USAGE:
     In order to use this script type the commands line below in the terminal:
     git clone https://github.com/dr-jesus/LinuxPasswordDicCracker.git
     cd LinuxPasswordDicCracker
     sudo python3 sha512dicCryptor.py
 
NOTE:
     - Tested on Parrot OS 64, for passwords hashed with SHA-512. 
     - Coded using Python 3.8.2.
     - Should run this program as root.

e-mail:
      jesus.dacoast@gmail.com

