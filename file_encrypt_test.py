import os
from cryptography.fernet import Fernet


def encrypt_file():
    filename = all_files
    key_file_enc = open(key_path, "rb").read()
    f = Fernet(key_file_enc)
    files_done = 0

    for i in filename:
        print("Encrypting", i)
        with open(i, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(i, "wb") as file:
            file.write(encrypted_data)

        files_done = files_done + 1

    print("Encrypted", files_done, "files")
    key_file_enc.close()


def decrypt_file():

    filename = all_files
    key_file_dec = open(key_path, "rb").read()
    fe = Fernet(key_file_dec)
    files_done = 0

    for i in filename:
        print(i)
        with open(i, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fe.decrypt(encrypted_data)
        with open(i, "wb") as file:
            file.write(decrypted_data)

        files_done = files_done + 1

    print("Decrypted", files_done, "files")
    key_file_dec.close()


def random_key():
    writing_key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(writing_key)


# dir_path = "F:/encription/test"
key_path = os.getcwd() + "/key.key"

all_files = []
random_key()
sure = "n"
while sure.lower() != "y":
    dir_path = input("\nType in directory to select >")
    print("You have selected", dir_path)
    sure = input("you sure? (y/n) >")

for root, d_names, f_names in os.walk(dir_path):
    for f in f_names:
        all_files.append(os.path.join(root, f))
        print(os.path.join(root, f))


choice = 0
while choice == 0:
    choice = int(input("Encrypt (1) or decrypt (2) >"))
    if choice == 1:
        encrypt_file()
    elif choice == 2:
        decrypt_file()
