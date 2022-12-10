import base64
from tkinter import *
import secrets
from tkinter import ttk
from cryptography.fernet import Fernet
from tkinter.filedialog import askopenfilename

root = Tk()

message = StringVar()
key = StringVar()
output = StringVar()
key_len = IntVar()
file_to_get = StringVar()
key_file_get = StringVar()
output_text = StringVar()


def encode():
    encoded_message = []

    key_encode = key.get()
    message_encode = message.get()

    key_encode = str(key_encode)
    message_encode = str(message_encode)

    if len(key_encode) >= len(message_encode):
        for i in range(len(str(message_encode))):
            key_c = str(key_encode)[i % len(str(key_encode))]
            encoded_message.append(chr((ord(str(message_encode)[i]) + ord(key_c)) % 256))
        output.set(base64.urlsafe_b64encode("".join(encoded_message).encode()).decode())


def decode():
    decoded_message = []

    key_decode = key.get()
    message_decode = message.get()

    key_decode = str(key_decode)
    message_decode = str(message_decode)

    message_decode = base64.urlsafe_b64decode(message_decode).decode()

    if len(key_decode) >= len(message_decode):
        for i in range(len(message_decode)):
            key_c = key_decode[i % len(key_decode)]
            decoded_message.append(chr((256 + ord(message_decode[i]) - ord(key_c)) % 256))
        output.set("".join(decoded_message))


def select_file():
    file_select = askopenfilename()
    file_to_get.set(file_select)


def select_key():
    key_select = askopenfilename()
    key_file_get.set(key_select)


def random_key():
    key_length = key_len.get()
    key.set(secrets.token_bytes(key_length))


def write_key():
    writing_key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(writing_key)


def load_key():
    return open(key_file_get.get(), "rb").read()


def encrypt_file():

    filename = file_to_get.get()
    key_file_enc = load_key()

    f = Fernet(key_file_enc)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

    output_text.set("Encrypted")


def decrypt_file():

    filename = file_to_get.get()
    key_file_dec = load_key()

    f = Fernet(key_file_dec)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)

    output_text.set("Decrypted")


root.geometry('500x300')
root.resizable(0, 0)
root.title("Encryption and shit")

tab_control = ttk.Notebook(root)

text_encryption_tab = ttk.Frame(tab_control)
file_encryption_tab = ttk.Frame(tab_control)

tab_control.add(text_encryption_tab, text="Text Encryption")
tab_control.add(file_encryption_tab, text="File Encryption")
tab_control.pack(expand=1, fill='both')

# #############################################################################
# ###--------------------------- Text Encryption ---------------------------###
# #############################################################################

Label(text_encryption_tab, text="Vernam cypher", font="arial 20 bold").pack()

Label(text_encryption_tab, font="arial 12 bold", text="Message").place(x=30, y=60)
Entry(text_encryption_tab, font='arial 10', textvariable=message, bg='ghost white', width="30").place(x=250, y=60)

Label(text_encryption_tab, font='arial 12 bold', text='Key').place(x=30, y=90)
Entry(text_encryption_tab, font='arial 10', textvariable=key, bg='ghost white', width="30").place(x=250, y=90)

Label(text_encryption_tab, font='arial 12 bold', text='Key Length (If Generating)').place(x=30, y=120)
Entry(text_encryption_tab, font='arial 10', textvariable=key_len, bg='ghost white', width="30").place(x=250, y=120)

Label(text_encryption_tab, font='arial 12 bold', text='Output').place(x=30, y=150)
Entry(text_encryption_tab, font='arial 10', textvariable=output, bg='ghost white', width="30").place(x=250, y=150)

Button(text_encryption_tab, font='arial 10 bold', text='Encode', padx=2, bg='LightGray',
       command=lambda: encode()).place(
    x=180, y=200)
Button(text_encryption_tab, font='arial 10 bold', text='Decode', padx=2, bg='LightGray',
       command=lambda: decode()).place(
    x=260, y=200)
Button(text_encryption_tab, font='arial 10 bold', text='Generate random key', padx=2, bg='LightGray',
       command=lambda: random_key()).place(
    x=175, y=240)

# #############################################################################
# ###--------------------------- File Encryption ---------------------------###
# #############################################################################

Label(file_encryption_tab, text="File Encryption", font="arial 20 bold").pack()

Button(file_encryption_tab, font='arial 10 bold', text='Select file', padx=2, bg='LightGray', command=lambda: select_file()).place(x=90, y=200)
Label(file_encryption_tab, font="arial 12 bold", text="File").place(x=30, y=60)
Entry(file_encryption_tab, font='arial 10', textvariable=file_to_get, bg='ghost white', width="45").place(x=150, y=60)

Label(file_encryption_tab, font="arial 12 bold", text="Key").place(x=30, y=90)
Entry(file_encryption_tab, font='arial 10', textvariable=key_file_get, bg='ghost white', width="45").place(x=150, y=90)

Label(file_encryption_tab, font="arial 12 bold", text="Output").place(x=30, y=120)
Entry(file_encryption_tab, font='arial 10', textvariable=output_text, bg='ghost white', width="45").place(x=150, y=120)

Button(file_encryption_tab, font='arial 10 bold', text='Select Key', padx=2, bg='LightGray', command=lambda: select_key()).place(x=190, y=200)
Button(file_encryption_tab, font='arial 10 bold', text='Generate Key', padx=2, bg='LightGray', command=lambda: write_key()).place(x=280, y=200)
Button(file_encryption_tab, font='arial 10 bold', text='Encrypt', padx=2, bg='LightGray', command=lambda: encrypt_file()).place(x=170, y=240)
Button(file_encryption_tab, font='arial 10 bold', text='Decrypt', padx=2, bg='LightGray', command=lambda: decrypt_file()).place(x=240, y=240)

root.mainloop()
