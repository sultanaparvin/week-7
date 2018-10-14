# -*- coding: utf-8 -*-
"""
Created on Thu Oct 11 19:26:32 2018

@author: Sultana
"""

import socket
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA  #Used PycrptoDome
from Crypto.Random import get_random_bytes #Used PycrptoDome
from Crypto.Cipher import PKCS1_OAEP

#Send messages over socket
def sendMessage(message,ip,port):
    s1 = socket.socket()
    s1.connect((ip,port))
    s1.send(message)
    response = s1.recv(1024)
    s1.close()
    return response

#Generate IV
def generateIV():
    return get_random_bytes(AES.block_size)

#Encrypt function
def encrypt(key, IV, rawData):
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    return encryptor.encrypt(rawData)

#Decrypt function
def decrypt(key, IV, encryptedData):
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    return decryptor.decrypt(encryptedData)

#Generate AES Key
def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()


print('Client')
#Send a request to get the certificate
response = sendMessage('GIVEMECERT'.encode(),'127.0.0.1',9500)
serverCertificate = response.decode() #get the certificate sent by the server

#to validate the certificate create a connection CA
response = sendMessage(serverCertificate.encode(),'127.0.0.1',9501)
publicKey = response.decode()
if publicKey == 'null':
    #say goodbye to server as we were not able to recognize it
    response = sendMessage('GOODBYE'.encode(),'127.0.0.1',9500)
    print('goodbye')
else:
    sessionCipher = generateIV()
    print('IV:')
    print(sessionCipher)
    print('public key :')
    print(publicKey)
    publicKey = publicKey.replace("\r\n", '')
    publicKeyObject = RSA.importKey(publicKey)
    cipherEncryptor = PKCS1_OAEP.new(publicKeyObject)
    print(sessionCipher)
    sessionCipherKeyEncryptedByPublicKey = cipherEncryptor.encrypt(sessionCipher)
    print(sessionCipherKeyEncryptedByPublicKey)
    response = sendMessage(('SESSIONCIPHER'+str(sessionCipherKeyEncryptedByPublicKey)).encode(),'127.0.0.1',9500)
    ackEncrypted = response.decode()
    print(ackEncrypted)
    AESPassword = 'test' 
    AESKey = getKey(AESPassword)
    ackDecrypte = decrypt(publicKey.encode(), sessionCipher, ackEncrypted)
    print(ackDecrypte)






    ##sessionCipherKeyEncryptedByPublicKey = publicKeyObject.encrypt(sessionCipher,32)
    #s1.send(sessionCipherKeyEncryptedByPublicKey.encode())





####
    # s1.send('IV'+IV.encode()) #Send IV
    # s1.send(encrypt(getKey(public_key),IV,'Hello'))



    # sessionCipherKey = getKey(public_key)
    # s1.send(sessionCipherKey.encode())



















#     s1.sendsessionCipherKey.encode())
#     #encryptedCipherKey = encrypt(public_key, generateIV(), sessionCipherKey)
#     #s1.send(("CIPHERKEY:" + encryptedCipherKey).encode())

#     #5
#     acknowledgement = s1.recv(1024).decode()
#     if decrypt(sessionCipherKey, generateIV(), acknowledgement) == sessionCipherKey:
#         #6
#         # TODO: Send some encrypted data to the server
#        encrypted = encrypt(public_key,generateIV(),"Hello")
#        s1.send(encrypted.encode())





# print(s.recv(1024))
# s1.close()





    



