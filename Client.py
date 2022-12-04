# -*- coding: utf-8 -*-
"""
Created on Tue Aug 23 23:15:07 2022

@author: teres
"""

import socket
import sys,os
import random
import hashlib
import RSA
import rc4
import threading

serverAddressPort   = ("127.0.0.1", 20002)

bufferSize          = 1024

NB=random.getrandbits(128)
K=random.getrandbits(128)
# Create a UDP socket at client side

UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
connection=True


clientName=input('You are client. Please eneter user name: ')
#send NB
NBToSend=str.encode(str(NB))
UDPClientSocket.sendto(NBToSend, serverAddressPort)

#send clientName
clientNameToSend=str.encode(clientName)
UDPClientSocket.sendto(clientNameToSend, serverAddressPort)

#receive NA
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
NA=msgFromServer[0]
NA=int(NA.decode('utf-8'))

#receive publicKey
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
pk=msgFromServer[0]
pk=pk.decode('utf-8')

        
#receive hostName
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
hostName=msgFromServer[0]
hostName=hostName.decode('utf-8')
print('Host is ' + hostName)

#verify pk with fingerprint
with open('Bob/fingerprint.pem', 'r') as f:
    lines=f.readlines()
    fingerprint=lines[0]
    hpk = hashlib.sha1(pk.encode()).hexdigest()
    if(hpk!=fingerprint):
        sys.exit('Public key mismatched. You are disconnected.')
        connection=False

        
# input user name and pw
if (connection==True):
    user = clientName
    user=user+'\n'
    while True:
        password = input('Enter password: ')
        if (len(password)==8):
            break
        else:
            print('Password length should be 8')
            
    #send user name to host
    userToSend         = str.encode(user)  
    UDPClientSocket.sendto(userToSend, serverAddressPort)
    
    #encrypt pw with RSA            
    pubKey, privKey = RSA.load_keys()
    pwAndK=password+str(K)
    ciphertext = RSA.encrypt(pwAndK, pubKey)
    
    #send encrypted pw to host
    UDPClientSocket.sendto(ciphertext, serverAddressPort)
    
    #receive confirmation from host
    msgFromServer = UDPClientSocket.recvfrom(bufferSize)
    msg = "Message from Server {}".format(msgFromServer[0])
    print(msg)
    if (msgFromServer[0].decode('utf-8')=='Connection Failed'):
        connection=False
        sys.exit("You are disconnected.")



if (connection==True):
    
    #hash by SHA-1: ssk = H(K,NB,NA)
    K_NB_NA=str(K)+str(NB)+str(NA)
    ssk=hashlib.sha1(K_NB_NA.encode())
    ssk_h=ssk.hexdigest() #string size 40
    
    m=''
    while (True):
        def send():
            while True:
                m = input("Enter message: ")
                #Disconnect
                if (m == "exit"):
                    m='Client disconnected'
                    #Compute integrity check value h
                    ssk_m=ssk_h+m #string, concat ssk and m
                    h=hashlib.sha1(ssk_m.encode()) #hash value of ssk and m
                    h_hex=h.hexdigest()  #string size 40
                     
                     #RC4 encryption
                    m_h=m+h_hex #concat message and h, string
                    ciphertext = rc4.encrypt(ssk_h, m_h) #string
                    ciphertext_b=ciphertext.encode() #to bytes
                    
                    # Sending a ciphertext to client
                    UDPClientSocket.sendto(ciphertext_b, serverAddressPort)
                    
                    os._exit(7)
                
                
                #Compute integrity check value h
                ssk_m=ssk_h+m #string, concat ssk and m
                h=hashlib.sha1(ssk_m.encode()) #hash value of ssk and m
                h_hex=h.hexdigest()  #string size 40
                 
                 #RC4 encryption
                m_h=m+h_hex #concat message and h, string
                ciphertext = rc4.encrypt(ssk_h, m_h) #string
                ciphertext_b=ciphertext.encode() #to bytes
                
                # Sending a ciphertext to client
                UDPClientSocket.sendto(ciphertext_b, serverAddressPort)

        def receive():
            while True:
                #Receive from client
                accept_m=True
                bytesAddressPair = UDPClientSocket.recvfrom(bufferSize)                  
                ciphertext_b=bytesAddressPair[0]  
                ciphertext=ciphertext_b.decode('utf-8') #to string
                
                #decryption
                m_h = rc4.decrypt(ssk_h, ciphertext)
                try:
                    messageLength=len(m_h)
                    h_hex=m_h[messageLength-40:]
                    
                    #Compute integrity check value h'
                    ssk_m_check=ssk_h+m_h[0:messageLength-40] #string, concat ssk and m
                    h_check=hashlib.sha1(ssk_m_check.encode()) #hash value of ssk and m
                    h_check_hex=h_check.hexdigest()  #string size 40
                    
                    #check if h'= h
                    if (h_hex==h_check_hex):
                        accept_m=True
                    else:
                        accept_m=False
                        print('Integrity check failed, message rejected.')
                    if (accept_m==True):   
                        msg = "Message from {}: {}".format(hostName, m_h[0:messageLength-40])
                
                        print(msg)
                except BaseException:
                    print('Decryption Error')
                    pass
        
        sender = threading.Thread(target=send, daemon=True);
        receiver = threading.Thread(target=receive, daemon=True);
        sender.start()  
        receiver.start()
        sender.join()  
        receiver.join()   
        
