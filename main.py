from tkinter import *
from tkinter import messagebox
import base64
import hashlib
import os
import cryptography
from cryptography.fernet import Fernet
import rsa
from Crypto.Cipher import AES,DES

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto import Random
from base64 import b64encode, b64decode



def encrypt():
	password = code.get()
	if password == "1234":
		screen1 = Toplevel(screen)
		screen1.title("Encryption")
		screen1.geometry("500x250")
		screen1.configure(bg="#ed3833")

		message = text1.get(1.0 , END)
		encode_message= message.encode("ascii")
		base64_bytes = base64.b64encode(encode_message)
		encrypt = base64_bytes.decode("ascii")
		
		Label(screen1 , text="ENCRYPT" , font = "arial" ,fg = "white" , bg = "#ed3833").place(x = 10 , y = 0)
		text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
		text2.place(x= 10 , y = 50 , width = 450 , height = 100)

		text2.insert(END , encrypt)

def decrypt():
	password = code.get()
	if password == "1234":
		screen2 = Toplevel(screen)
		screen2.title("Decryption")
		screen2.geometry("500x200")
		screen2.configure(bg="#00bd56")

		message = text1.get(1.0 , END)
		decode_message= message.encode("ascii")
		base64_bytes = base64.b64decode(decode_message)
		decrypt = base64_bytes.decode("ascii")
		
		Label(screen2 , text="DECRYPT" , font = "arial" ,fg = "white" , bg = "#00bd56").place(x = 10 , y = 0)
		text2= Text(screen2 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
		text2.place(x= 10 , y = 50 , width = 450 , height = 100)


		text2.insert(END , decrypt)



def fernet_encrypt():

	screen1 = Toplevel(screen)
	screen1.title("Encryption")
	screen1.geometry("500x250")
	screen1.configure(bg="#ed3833")

	message = text1.get(1.0 , END)

	key = cryptography.fernet.Fernet.generate_key()

	fernet = cryptography.fernet.Fernet(key)
	encrypted_message = fernet.encrypt(message.encode('utf-8'))

	Label(screen1 , text="ENCRYPT" , font = "arial" ,fg = "white" , bg = "#ed3833").place(x = 10 , y = 0)
	text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text2.place(x= 10 , y = 50 , width = 450 , height = 100)

	text2.insert(END , encrypted_message)


	screen2 = Toplevel(screen)
	screen2.title("Secret Key")
	screen2.geometry("500x250")
	screen2.configure(bg="#ed3833")

	Label(screen2 , text="generated_key" , font = "arial" ,fg = "white" , bg = "#ed3833").place(x = 10 , y = 0)
	text3= Text(screen2 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text3.place(x= 10 , y = 50 , width = 450 , height = 100)

	text3.insert(END , key)



def fernet_decrypt():
	screen1 = Toplevel(screen)
	screen1.title("Decryption")
	screen1.geometry("500x250")
	screen1.configure(bg="#00bd56")

	encrypted_message = text1.get(1.0 , END)
	key = code.get()

	fernet = cryptography.fernet.Fernet(key)
	decrypted_message = fernet.decrypt(bytes(encrypted_message,'utf-8'))


	Label(screen1 , text="DECRYPT" , font = "arial" ,fg = "white" , bg = "#00bd56").place(x = 10 , y = 0)
	text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text2.place(x= 10 , y = 50 , width = 450 , height = 100)

	text2.insert(END , decrypted_message)
    


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]


def aes_encrypt():
	screen1 = Toplevel(screen)
	screen1.title("Encryption")
	screen1.geometry("500x250")
	screen1.configure(bg="#ed3833")


	# simple_key = get_random_bytes(32)
	password = code.get()
	
	aes = AESCipher(password)
	message = text1.get(1.0 , END)
	ciphered_data = aes.encrypt(message)


	Label(screen1 , text="ENCRYPT" , font = "arial" ,fg = "white" , bg = "#ed3833").place(x = 10 , y = 0)
	text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text2.place(x= 10 , y = 50 , width = 450 , height = 100)

	text2.insert(END , ciphered_data)


def aes_decrypt():
	screen1 = Toplevel(screen)
	screen1.title("Decryption")
	screen1.geometry("500x250")
	screen1.configure(bg="#00bd56")

	password = code.get()
	aes = AESCipher(password)

	message = text1.get(1.0 , END)

	decrypted_message = aes.decrypt(message)
	


	Label(screen1 , text="DECRYPT" , font = "arial" ,fg = "white" , bg = "#00bd56").place(x = 10 , y = 0)
	text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text2.place(x= 10 , y = 50 , width = 450 , height = 100)

	text2.insert(END , decrypted_message)


def des_encrypt():
	screen1 = Toplevel(screen)
	screen1.title("Encryption")
	screen1.geometry("500x250")
	screen1.configure(bg="#ed3833")

	key1 = code.get()
	key_bytes = key1.encode("utf-8")
	key = base64.b64encode(key_bytes)
	
	
	message = text1.get(1.0 , END)
	data = message.encode('utf-8')
	
	BLOCK_SIZE = 32

	des = DES.new(key, DES.MODE_ECB)
	padded_text = pad(data, BLOCK_SIZE)
	ciphered_data = des.encrypt(padded_text)



	Label(screen1 , text="ENCRYPT" , font = "arial" ,fg = "white" , bg = "#ed3833").place(x = 10 , y = 0)
	text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text2.place(x= 10 , y = 50 , width = 450 , height = 100)

	text2.insert(END , ciphered_data)

def des_decrypt():
	screen1 = Toplevel(screen)
	screen1.title("Decryption")
	screen1.geometry("500x250")
	screen1.configure(bg="#ed3833")

	key1 = code.get()
	key_bytes = key1.encode("utf-8")
	key = base64.b64encode(key_bytes)
	
	
	message = text1.get(1.0 , END)
	data = message.encode('utf-8')

	des = DES.new(key, DES.MODE_ECB)
	decrypted_message = des.decrypt(data)

	


	Label(screen1 , text="DECRYPT" , font = "arial" ,fg = "white" , bg = "#ed3833").place(x = 10 , y = 0)
	text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text2.place(x= 10 , y = 50 , width = 450 , height = 100)

	text2.insert(END , decrypted_message)




def reset():
		code.set("")
		text1.delete(1.0 , END)


def main_screen():

	global screen
	global code
	global text1
	screen = Tk()
	screen.geometry("600x800")
	screen.title("Encryption and Decryption of Message")

	# icon
	# image_icon = PhotoImage(file="")
	# screen.iconphoto(False , image_icon)
	

	

	Label(text="Enter text to Encrypt or Decrypt" , fg="black" , font= "impack 14 bold").place(x=10,y=10)
	text1= Text(font="Robote 20" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
	text1.place(x= 10 , y = 50 , width = 580 , height = 100)


	Label(text= "Enter the secret key for encryption and decryption",fg="black" ,font=("calbri" , 10)).place(x=10 , y=170)

	code = StringVar()

	Entry(textvariable=code , width = 30 , bd = 0 , font = ("arial",25) , show = "*").place(x=10 ,y = 200)

	Button(text="Base 64 ENCRYPT" , height="2" , width = 20 ,bg = "#ed3833" , fg = "white" , bd = 0 , command= encrypt).place(x=10 , y = 300)
	Button(text="Base 64 DECRYPT" , height="2" , width = 20 ,bg = "#00bd56" , fg = "white" , bd = 0 , command= decrypt).place(x=400 , y = 300)


	Button(text="Fernet ENCRYPT" , height="2" , width = 20 ,bg = "#ed3833" , fg = "white" , bd = 0 , command= fernet_encrypt).place(x=10 , y = 350)
	Button(text="Fernet DECRYPT" , height="2" , width = 20 ,bg = "#00bd56" , fg = "white" , bd = 0 , command= fernet_decrypt).place(x=400 , y = 350)


	Button(text="AES ENCRYPT" , height="2" , width = 20 ,bg = "#ed3833" , fg = "white" , bd = 0 , command= aes_encrypt).place(x=10 , y = 400)
	Button(text="AES DECRYPT" , height="2" , width = 20 ,bg = "#00bd56" , fg = "white" , bd = 0 , command= aes_decrypt).place(x=400 , y = 400)

	# Button(text="DES ENCRYPT" , height="2" , width = 20 ,bg = "#ed3833" , fg = "white" , bd = 0 , command= des_encrypt).place(x=10 , y = 450)
	# Button(text="DES DECRYPT" , height="2" , width = 20 ,bg = "#00bd56" , fg = "white" , bd = 0 , command= des_decrypt).place(x=400 , y = 450)


	Button(text="RESET" , height="2" , width = 20 ,bg = "#1089ff" , fg = "white" , bd = 0 , command=reset).place(x=200 , y = 500)


	screen.mainloop()

main_screen()




































































































































# def aes_encrypt1():
# 	screen1 = Toplevel(screen)
# 	screen1.title("Encryption")
# 	screen1.geometry("400x250")
# 	screen1.configure(bg="#ed3833")


# 	# simple_key = get_random_bytes(32)
# 	password = code.get()
# 	salt = b"7h Z\xcaP\xc3\x985\xb6\xacJ\xd11\xact\xce\x85P\xb3\xaaI\xb4W\xd3\x9e\xce'\x9d\xa8\xf8l"

# 	key = PBKDF2(password , salt , dkLen=32)

# 	message = text1.get(1.0 , END)

# 	cipher = AES.new(key , AES.MODE_CBC)
# 	ciphered_data = cipher.encrypt(pad(message,16))


# 	Label(screen1 , text="ENCRYPT" , font = "arial" ,fg = "white" , bg = "#ed3833").place(x = 10 , y = 0)
# 	text2= Text(screen1 , font="Rpbote 10" , bg="white" , relief= GROOVE , wrap= WORD , bd = 0)
# 	text2.place(x= 10 , y = 50 , width = 450 , height = 100)

# 	text2.insert(END , ciphered_data)
	





