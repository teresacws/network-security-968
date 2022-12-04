# -*- coding: utf-8 -*-
"""
Spyder Editor

Reference: https://pythontic.com/modules/socket/udp-client-server-example
"""
import socket
import sys,os
import RSA
import random
import hashlib
import rc4
import pem
import threading

localIP     = "127.0.0.1"

localPort   = 20002

bufferSize  = 1024

NA=random.getrandbits(128)


# Create a datagram socket

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

 

# Bind to address and ip

UDPServerSocket.bind((localIP, localPort))

hostName=input('You are host. Please eneter user name: ')
#awaiting user validation
print("UDP server up and listening. Waiting user validation")



#verify user name
user_match=False
pw_match=False
while (user_match==False) or (pw_match==False):
    print('Waiting for client...')
    #receive NB

    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    NB=bytesAddressPair[0]

    address = bytesAddressPair[1]
    NB=NB.decode('utf-8')
    NB=int(NB)


    #receive clientName

    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    clientName=bytesAddressPair[0]
    address = bytesAddressPair[1]
    clientName=clientName.decode('utf-8')
    print('Client is ' + clientName)

    #send NA
    NAToSend=str.encode(str(NA))
    UDPServerSocket.sendto(NAToSend, address)

    #send publicKey
    certs = pem.parse_file("Alice/pubkey.pem")
    certs[0] = str(certs[0]).replace('-----BEGIN RSA PUBLIC KEY-----', '')
    certs[0] = str(certs[0]).replace('-----END RSA PUBLIC KEY-----', '')
    strcerts=str(certs[0])
    strcerts=strcerts[1:]
    strcerts=strcerts[:-1]
    PK=strcerts[:-1]
    PKToSend=str.encode(PK)
    UDPServerSocket.sendto(PKToSend, address)


    #send hostName
    hostNameToSend=str.encode(hostName)
    UDPServerSocket.sendto(hostNameToSend, address)
    
    with open('Alice/user_pw.txt','r') as f:
        lines=f.readlines()
        user1=str(lines[0])
        bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
        user = bytesAddressPair[0]
        address = bytesAddressPair[1]

        
        if (user1==user.decode('utf-8')):
            print('user matched')
            
            user_match=True
        else:
            print('no user exist')
            
        #verify password
    with open('Alice/user_pw.txt','r') as f:
        lines=f.readlines()
        pw1=str(lines[1])
        bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
        ciphertext = bytesAddressPair[0]
        address = bytesAddressPair[1]
        
        #decrypt password
        error=False
        pubKey, privKey = RSA.load_keys()
        pwAndK = RSA.decrypt(ciphertext, privKey)
        password = pwAndK[0:8]
        K=int(pwAndK[8:])
        password= hashlib.sha1(password.encode())
        password=password.hexdigest()
        if (pw1==password):
            print('password matched')
            pw_match=True
        else:
            print('password incorrect')
        if (user_match==False) or (pw_match==False):
            UDPServerSocket.sendto('Connection Failed'.encode(), address)


#print client IP
clientIP  = "{} IP Address:{}".format(clientName, address)
print(clientIP)
        
#send confirmation to client
UDPServerSocket.sendto(b'Connection Okay', address)


#hash by SHA-1: ssk = H(K,NB,NA)
K_NB_NA=str(K)+str(NB)+str(NA)
ssk=hashlib.sha1(K_NB_NA.encode())
ssk_h=ssk.hexdigest() #string size 40

# Listen for incoming datagrams
m=''
while(True):
    def send():
        while True:
            m = input("Enter message: ")
            #Disconnect
            if (m == "exit"):
                m='Host disconnected'
                #Compute integrity check value h
                ssk_m=ssk_h+m #string, concat ssk and m
            
                h=hashlib.sha1(ssk_m.encode()) #hash value of ssk and m
                h_hex=h.hexdigest()  #string size 40
            
                 
                 #RC4 encryption
                m_h=m+h_hex #concat message and h, string
                ciphertext = rc4.encrypt(ssk_h, m_h) #string
                ciphertext_b=ciphertext.encode() #to bytes
                
                # Sending a ciphertext to client
                UDPServerSocket.sendto(ciphertext_b, address) 
                
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
            UDPServerSocket.sendto(ciphertext_b, address) 
  
    
    def receive():
        while True:
            #Receive from client
            accept_m=True
            bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
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
                    clientMsg = "Message from {}:{}".format(clientName,m_h[0:messageLength-40])
                    
                    
                    print(clientMsg)
            except BaseException:
                print('Decryption Error')
                pass
        
    sender = threading.Thread(target=send, daemon=True);
    receiver = threading.Thread(target=receive, daemon=True);
    sender.start()  
    receiver.start()
    sender.join()  
    receiver.join()   
  
