# -*- coding: utf-8 -*-
"""
Created on Thu Aug 25 13:36:11 2022

@author: teres
"""
import hashlib
import os

current_directory = os.getcwd()
final_directory = os.path.join(current_directory, r'Alice')
if not os.path.exists(final_directory):
   os.makedirs(final_directory)
   

final_directory = os.path.join(current_directory, r'Bob')
if not os.path.exists(final_directory):
   os.makedirs(final_directory)

user = input('Enter user name: ')
correctLen=False
while (correctLen==False):
    password = input('Enter password (8 alphanumeric characters): ')
    if (len(password)!=8):
        print('Password length must be 8.')
    else:
        break

#Hash user pw
pwHash= hashlib.sha1(password.encode())
pwHex=pwHash.hexdigest()

with open('Alice/user_pw.txt','w') as f:
    f.write(user + '\n')
    f.write(pwHex)
    print('Saved user name and password to user_pw.txt')
