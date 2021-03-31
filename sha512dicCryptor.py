#!/usr/bin/python3
###############################################################################
# Mon,April 20th 2020 - 21:51 GMT+1                                           #
# Coder: jesus dacoast                                                        #
# Email: jesus.dacoast@gmail.com                                              #
# A simple python3 script for the decryption of linux hashed passwords with   #
# default round set as -R 5000 , using the /etc/shadow file and a passwords   #
# dictionary of choice.                                                       #
# Version: V1.1                                                                #
# [Tested and proved on Parrot Linux OS 64.]                                  #
###############################################################################
import sys
import os
import crypt
from six.moves import input

# raw_input/input for Python 2.x and 3.x respectively is fixed by: from six.moves import input

PASS_DCT = "dictionary.txt"  # Default Password Dictionary
# PASS_DCT = "/usr/share/wordlists/dirb/others/best1050.txt"  # Password Dictionary
SHADOW_F = "shadow.txt"  # Shadow File must be root to access this file


def intro():
    print(" /#########################################################\ ")
    print(" ()##~  Linux hashed password Cracker using Dictionary ~##() ")
    print(" ()######~~~~~  jesus.dacoast[AT]gmail[DOT]com ~~~~~######() ")
    print(" ()                      Version 1.1                      () ")
    print(" () nb: Tested on Parrot/OS for hashed pwd at the default () ")
    print(" () round of -R 5000, must be root to access etc/shadow   () ")
    print(" ()                        -ENJOY-                        () ")
    print(" \#########################################################/ \n")


def checkFiles():
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
        print("[--] Exiting program...")
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
        dct = dicLoc  # user choosen dictionary
    else:
        dct = PASS_DCT  # use local dictionary
    if cryptedPasswd[0] == "$":  # 1st letter is $ for valid accounts
        ash = cryptedPasswd.split("$")[1:4]  # [Hash Algorithm, Salt, Hashed password]
        if ash[0] == "6":
            hashT = ash[0]
            salt = ash[1]
            hash = ash[2]
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
                # print(word) #if something going bad with your dict. try to incomment this and c
                cryptWord = crypt.crypt(word, "$6$" + salt)
                if cryptWord == cryptedPasswd:
                    print(
                        "[++] Password Found For User [ {} ] :: [ {} ] \n".format(
                            user, word
                        )
                    )
                    return
            print("[-] Password Not Found.\n")
            return
        elif ash[0] == "1":
            hashT = ash[0]
            salt = ash[1]
            hash = ash[2]
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
                # print(word) #if something going bad with your dict. try to incomment this and c
                cryptWord = crypt.crypt(word, "$1$" + salt)
                if cryptWord == cryptedPasswd:
                    print(
                        "[++] Password Found For User [ {} ] :: [ {} ] \n".format(
                            user, word
                        )
                    )
                    return
            print("[-] Password Not Found.\n")
            return
            
        elif ash[0] == "5":
            print("Not made to Crack SHA-256 Hashes yet!")
            sys.exit()
        # elif ash[0] == "2a"
        else:
            print("Not made to Crack Blowfish Hashes yet!")
            sys.exit()

    elif cryptedPasswd[0] == "*":
        print("[-] No password can be used to access the account with [!]\n")
    elif cryptedPasswd[0] == "!":
        print("[-] The Account with [*] is LOCKED!\n")
    else:
        print(" Hello World! :D")


def main():
    intro()
    global dicLoc
    dicLoc = input(
        "Please, enter dictionary file location or user local dictionary: \n --> "
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
                    print("[+] Linux System User Found: {}".format(user))
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
