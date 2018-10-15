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


AESPassword = 'test' 


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

#Add padding
def pad(data):
    length = 16 - (len(data) % 16)
    data += chr(length)*length
    return data

#Remove padding
def unpad(data):
    return data[:-data[-1]]

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
    publicKey = publicKey.replace("\r\n", '')
    publicKeyObject = RSA.importKey(publicKey)

    cipherEncryptor = PKCS1_OAEP.new(publicKeyObject)
    sessionCipherKeyEncryptedByPublicKey = cipherEncryptor.encrypt(sessionCipher)
    response = sendMessage(('SESSIONCIPHER'+str(sessionCipherKeyEncryptedByPublicKey)).encode(),'127.0.0.1',9500)
    ackEncrypted = response
    #print("ACK Encrypted: ", ackEncrypted)
    AESKey = getKey(AESPassword)
    ackDecrypte = decrypt(AESKey, sessionCipher, ackEncrypted)
    ackDecrypte = unpad(ackDecrypte) #Remove the padding
    if ackDecrypte.decode() == 'ACK': #This means that we got the right acknowledgement that we expected
        #Send the message
        data = "Hello"
        data = "MSG" + data
        data = pad(data) #Padding
        AESKey = getKey(AESPassword)
        encryptedMessage = encrypt(AESKey, sessionCipher, data.encode('utf-8'))
        encryptedMessageFromServer = sendMessage(str(encryptedMessage).encode(),'127.0.0.1',9500)
        AESKey = getKey(AESPassword)
        dcrytpedMessageFromServer = decrypt(AESKey, sessionCipher, encryptedMessageFromServer)
        print("Message from server:"+str(unpad(dcrytpedMessageFromServer).decode()))