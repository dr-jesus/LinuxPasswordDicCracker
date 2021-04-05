#!/usr/bin/python3
###############################################################################
# First release on:                                                           #
# Mon,April 20th 2020 - 21:51 GMT+1                                           #
# Coder: jesus dacoast                                                        #
# Email: jesus.dacoast@gmail.com                                              #
# A simple python3 script for the decryption of linux hashed passwords with   #
# default round set as -R 5000 , using the /etc/shadow file and a passwords   #
# dictionary of choice.                                                       #
# Version: V1.2                                                              #
# [Tested and proved on Parrot Linux OS 64.]                                  #
###############################################################################
import sys
import os
import crypt
from six.moves import input
from colorama import Fore, Style, Back

# raw_input/input for Python 2.x and 3.x respectively is fixed by: from six.moves import input

PASS_DCT = "dictionary.txt"  # Default Password Dictionary
# PASS_DCT = "/usr/share/wordlists/dirb/others/best1050.txt"  # Password Dictionary
SHADOW_F = "shadow.txt"  # "/etc/shadow" Shadow File must be root to access this file


def intro():
    print(" /#########################################################\ ")
    print(" ()##~  " + Fore.WHITE + "Linux hashed password Cracker using Dictionary" + Style.RESET_ALL + " ~##() ")
    print(" ()######~~~~~" + Fore.WHITE + " jesus.dacoast[AT]gmail[DOT]com  " + Style.RESET_ALL + "~~~~~######() ")
    print(" ()                      Version 1.1                      () ")
    print(" ()" + Fore.WHITE + " nb: Tested on Parrot/OS for hashed pwd at the default " + Style.RESET_ALL + "()")
    print(" ()" + Fore.WHITE + "  round of -R 5000, must be root to access etc/shadow " + Style.RESET_ALL + " ()")
    print(" ()" + Fore.RED + "                        -ENJOY-" + Style.RESET_ALL + "                        ()")
    print(" \#########################################################/ \n")


def checkFiles():
    # Check the existance of files
    dic = shd = False
    if dicLoc == "" and os.path.isfile(PASS_DCT):
        print(" --> Using Local dictionary...\n")
        print("[+] Program Starting...OK")
        print("[+] Dictionary file exists...OK")
        dic = True
    elif os.path.exists(dicLoc) == True:
        print("dic: " + dicLoc + "\n")
        print("[+] Program Starting...OK")
        print("[+] Dictionary file exists...OK")
        dic = True
    else:
        print("[-] Dictionary file doesn't exist...!")
        print("[-] Please Be Sure of The Dictionary File Path !")

    if os.path.isfile(SHADOW_F):
        print("[+] System Shadow file exists...OK\n")
        shd = True
    else:
        print("[-] Shadow file doesn't exist...!")

    if not shd or not dic:
        print("[--] Exiting program...\n")
        sys.exit()


def hashType(i):
    # using of a dictionary instead of switch case
    switcher = {
        "1": "Hash type is -> MD5 ",
        "5": "Hash type is -> SHA-256 ",
        "6": "Hash type is -> SHA-512 ",
        "2a": "Hash type is -> Blowfish ",
    }
    return switcher.get(i, "[-] Unknown Hash type...!")


def checkPasswd(user, cryptedPasswd):
    if dicLoc != "":
        dct = dicLoc  # use choosen dictionary
    else:
        dct = PASS_DCT  # use local dictionary
    if cryptedPasswd[0] == "$":  # 1st letter is $ for valid accounts
        ash = cryptedPasswd.split("$")[1:4]  # [Hash Algorithm, Salt, Hashed password]

        hashT = ash[0]
        salt = ash[1]
        hash = ash[2]
        decryptPasswd(dct, cryptedPasswd, ash, hashT, salt, hash, user)

    elif cryptedPasswd[0] == "*":
        print(Fore.RED + "[-] No password can be used to access the account with [!]")
    elif cryptedPasswd[0] == "!":
        print(Fore.RED + "[-] The Account with [*] is LOCKED!")
    else:
        print(" Hello World! :D")
    print(Style.RESET_ALL)


def decryptPasswd(dct, cryptedPasswd, ash, hashT, salt, hash, user):
    if ash[0] in ("1", "5", "6"):
        hashT = ash[0]
        salt = ash[1]
        hash = ash[2]
        print("[#] Shadow Line: " + cryptedPasswd)  # hash algorithm + salt + hashed word
        print("[+] Hash: {}".format(hashType(hashT)))
        print("[+] Salt is: {}".format(salt))
        print("[+] Hashed password is: {}".format(hash))
        print("[*] Cracking Password For: {}".format(user))

        dictFile = open(dct, "rt")  # open file as read text file
        for word in dictFile.readlines():
            word = word.replace(
                " ", ""
            ).strip()  # remove space, remove leading and trailing
            # word = word.strip("\n")  # eliminer les sauts des lignes
            # print(word) #if something going bad with your dict. try to incomment this and C
            cryptWord = crypt.crypt(word, "$" + ash[0] + "$" + salt)
            if cryptWord == cryptedPasswd:
                success(user, word)
                return
        print(Fore.RED + "[-] Password Not Found...!")
        print(Style.RESET_ALL)
        return
    ''' elif ash[0] == '2a'
        print("Not made to Crack Blowfish Hashes yet!")
        sys.exit() 
    '''


def success(user, word):
    print(
        Fore.BLUE
        + "[++] Password Found For User [ {} ] :: [ {} ] ".format(
            user, word
        )
    )
    print(Style.RESET_ALL)
    return


def main():
    intro()
    global dicLoc
    print("[==] NB: Tested Successfully with MD5, SHA-256 & SHA-512 Hash Algorithms.")
    dicLoc = input(
        "Please, enter dictionary file location or just press enter to use local dictionary: \n --> "
    )
    checkFiles()
    try:
        # shadowFile = open(SHADOW_F, "r")  # should be root to open this file
        with open(SHADOW_F, "r") as shadowFile:  # readonly mode
            for line in shadowFile.readlines():
                if ":" in line:
                    user = line.split(":")[
                        0
                    ]  # take the 1st part which contains the username
                    print("[+] Linux System User Found: " + Fore.WHITE + "{}".format(user))
                    print(Style.RESET_ALL)
                    cryptedPasswd = line.split(":")[
                        1
                    ]  # 2nd part contains the hashed password
                    checkPasswd(
                        user, cryptedPasswd
                    )  # try 2 crack it with the dictionary
    except IOError as er:
        print("[-] File NOT Accessible: {}".format(er))
        print("[-] U Should be root to access {}".format(SHADOW_F))


if __name__ == "__main__":
    main()

# generate a hashed password with openssl using SHA-512
# openssl passwd -6 -salt [yourSlatHere] [passwd2Crypt]
