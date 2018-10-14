# -*- coding: utf-8 -*-
"""
Created on Thu Oct 11 19:26:32 2018

@author: Sultana
"""

import socket

#CA_DATABASE is a dictionry containing a few pairs of certificate and public keys
# certificate : public_key
CA_DATABASE = {
    'KSHUEYG&W*YEWUIEY&' : "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhu6JCVdciOo7DmF3MOLE\npCMv1jXEzYXfy7UpR0EGEeQ5UiLSvUx6ZMiFXwfeDH4toYCtDAa6vX5b/dwxbStA\n+l0Gn0tZOWibmtjShhB26jEcnwRI8wjxw0lLvKCKfGgaAEcTDnNWYqmrQ8DdEUmX\nqGDn/79U6GZUiHvKtCRhjLJxTPWEYbywVkBtxWIVqY0I/PALT7NF+6ehPHV+ScoJ\nKWJxdBJhoy3j3RRveIm81GtsR9uqYM5mknDbJWg1BAHejhgGgTE2kfHkP45OLX4v\nRlh5zInOgIsNdX10TAJLWAj3vjf7kGf2u6OLzzU0BigSTrppprghblq5nmEPJtY8\nOQIDAQAB\n-----END PUBLIC KEY-----",
}

#Validate Certificate
def validateCertificate(certificate = ""):
    if certificate in CA_DATABASE.keys(): #if certificate exist return the public_key associated with it
        return CA_DATABASE.get(certificate)
    else: #If provided certificate is not in CA_DATABASE return null
        return "null"


print('CA')
s = socket.socket()
s.bind(('',9501))
s.listen(5)
while True:
    conn, addr = s.accept()
    certificate = conn.recv(1024) #Get the certificate from client
    result = validateCertificate(certificate.decode())
    conn.send(result.encode()) #send the result (null OR public_key) back to client
    s.close()