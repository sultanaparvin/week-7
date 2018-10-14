# -*- coding: utf-8 -*-
"""
Created on Thu Oct 11 19:26:32 2018

@author: Sultana
"""

import socket
import ast
#from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA  #Used PycrptoDome
from Crypto.Random import get_random_bytes #Used PycrptoDome
from Crypto.Cipher import PKCS1_OAEP

certificate = 'KSHUEYG&W*YEWUIEY&'
public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhu6JCVdciOo7DmF3MOLE\npCMv1jXEzYXfy7UpR0EGEeQ5UiLSvUx6ZMiFXwfeDH4toYCtDAa6vX5b/dwxbStA\n+l0Gn0tZOWibmtjShhB26jEcnwRI8wjxw0lLvKCKfGgaAEcTDnNWYqmrQ8DdEUmX\nqGDn/79U6GZUiHvKtCRhjLJxTPWEYbywVkBtxWIVqY0I/PALT7NF+6ehPHV+ScoJ\nKWJxdBJhoy3j3RRveIm81GtsR9uqYM5mknDbJWg1BAHejhgGgTE2kfHkP45OLX4v\nRlh5zInOgIsNdX10TAJLWAj3vjf7kGf2u6OLzzU0BigSTrppprghblq5nmEPJtY8\nOQIDAQAB\n-----END PUBLIC KEY-----"
private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAhu6JCVdciOo7DmF3MOLEpCMv1jXEzYXfy7UpR0EGEeQ5UiLS\nvUx6ZMiFXwfeDH4toYCtDAa6vX5b/dwxbStA+l0Gn0tZOWibmtjShhB26jEcnwRI\n8wjxw0lLvKCKfGgaAEcTDnNWYqmrQ8DdEUmXqGDn/79U6GZUiHvKtCRhjLJxTPWE\nYbywVkBtxWIVqY0I/PALT7NF+6ehPHV+ScoJKWJxdBJhoy3j3RRveIm81GtsR9uq\nYM5mknDbJWg1BAHejhgGgTE2kfHkP45OLX4vRlh5zInOgIsNdX10TAJLWAj3vjf7\nkGf2u6OLzzU0BigSTrppprghblq5nmEPJtY8OQIDAQABAoIBAApDtB4HTM1HkEWI\nSZJo9c+Ms7NmdLmzwPIUrnayrh0HUQr8Bi8LVdY74NV5Wj12Dc+W49Mh4evPZH0b\n1pC49SD2ma3dhASXfhrZ+q3jK8CmCsjYARqn6AhUl5PaXJ6ZJr01qu/y+zPXN2WY\nktihUg2njY6JhhKF0lFtpV5t1BPpVOjrBAzVkl4b31JCzVau4ceZqlY9Jt/BDsIY\nyMsuGWhrDmCqK+Xjw7YTc07/P1OFX/ubx9R09aqXisdA/NeNnf4iifpUkq3sXfxB\npDC6PGyKkOykEgt1/8muvdpRPtrG75dGLF4dL/mrAKFZtoVG9ueDnbnZQMBpCVt/\nE55qfPkCgYEAuDnTIsmRACn/vCWUokx3a+iZZxVpQFR6TBCMcc56j9s5Jppddh3j\nfM3gH8D0/95IN6yaKEvr1crc2Dn0RMJIku5eGsvAZF9zZHsRBxG/U0QHlBIplWV4\nEPwzVCcyM7GCI7TlVD3bOamOXzx1d6di8bymiG+yARxVXMGsa83yAE0CgYEAu4BB\nKqITIg4zhsRHlDO2KGpm7B7/bpbgl1OgZUqci0bLaVCNHxJjnBXYgWZerUK2zshN\nEJaaafucDd4WqIUsNj/1esyYsWlBX3Z1S7X5zNjNCP59jzddexCwuAfl+96cRfF1\nLbAUN9Pf6PRLVZ8caTr9JUEJvb9uQTwW8Iz6wZ0CgYBqRJDSREtsOM3YDiWK6WkJ\nygaTO/qWrSROtE0PaPex+9cfuXOoKt2KpIdgScIJxoMJ+nqCPCkyDe8Om3+YGioa\n9305H8c/HwBFOeg8l7Qxp9BnTYLHNtznj1Nce6+tuftD9ZlD2tqWjIQf05Q/DUM6\nBoRZt3SKx3lGJEH9fbLXEQKBgGSNcWU1qeEXkJZzaJeX69ZcyXlTXlSmYSeGV3w6\nuR0QCEIgSq4hJH4uUP+EML3mCzd1v65ntcOkhZoCQlB5qq4lOrZyRmjOM5rIYjsK\nCj7K/ZoXMKq/XEiFOOBYjAO47EGuLdMknJMb8vZxHH18aLYeRmfWKy0xHiWp3ft+\n/3MZAoGBALTSoKUapw4E43SbPXcZDohjFuEF8q16YdZO7jNtYdEiE4aqZxponvOu\nBxyCHGvoD0+c4EVQRvKEnZES4nSGDDui5gUzT8Xvd8keYIUdoB1aJoFV62ckg62o\ntdJcz5ApWWjreipu2BcI5p8GQlrOzZncBIAxFSKIN5aDlLreGIiS\n-----END RSA PRIVATE KEY-----"

#Generate RSA
def generateRSA(bits):   
    key = RSA.generate(2048)  
    public_key = key.publickey().exportKey("PEM")
    private_key = key.exportKey("PEM")
    print('Public:')
    print(public_key)
    print('Private:')
    print(private_key)

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




print('Server')
s = socket.socket()
s.bind(('',9500))
s.listen(5)
while True:
    conn, addr = s.accept()
    clientmessage = conn.recv(1024)
    clientmessageDecoded = clientmessage.decode()
    print(clientmessageDecoded)
    if clientmessageDecoded.startswith('GIVEMECERT') : #This means that this is the first request
        conn.send(certificate.encode()) #Send the certificate to client
    elif clientmessageDecoded.startswith('GOODBYE'):
        # Check if response is goodbye , then client didn't recognize us
        print('Error in connection to client')
        s.close()
    elif clientmessageDecoded.startswith('SESSIONCIPHER'):
        print("CIPHER") 
        sessionCipherReceivedFromClientEncrypted = clientmessageDecoded[13:]
        #sessionCipherReceivedFromClientEncrypted = sessionCipherReceivedFromClientEncrypted.encode()
        print(sessionCipherReceivedFromClientEncrypted)
        private_key = private_key.replace("\r\n", '')
        privateKeyObject = RSA.importKey(private_key)
        cipherDecryptor = PKCS1_OAEP.new(privateKeyObject)
        sessionCipherReceivedFromClientDecrypted = cipherDecryptor.decrypt(ast.literal_eval(str(sessionCipherReceivedFromClientEncrypted)))
        print('IV:')
        print(sessionCipherReceivedFromClientDecrypted)
        #Send acknowledgement
        AESPassword = 'test' 
        AESKey = getKey(AESPassword)
        encryptedACK = encrypt(AESKey, sessionCipherReceivedFromClientDecrypted, "ACK")
        conn.send(encryptedACK.encode())
        s.close()


