1. Create user
	1.1 Run user_pw.py in terminal
	1.2 Enter user name and password. Password should contain exactly 8 alphanumeric characters. 
	1.3 Two folders: Alice and Bob are created in current directory.
	1.4 User information is stored in Alice/user_pw.txt
2. Generate key pair
	2.1 Run GenKey.py in terminal
	2.2 Keys are stored in Alice folder. Fingerprint of public key is stored in Bob folder.
3. Main programme
	3.1 Run Host.py in terminal
	3.2 Host can enter any name. i.e. Alice
	3.3 Run Client.py in another terminal
	3.4 Client must enter the same user name and password as in Step 1. Otherwise, client will disconnect.
	3.5 If connection failed, restart Client.py and re-enter name and password. 
	3.6 If connection Okay, communication starts. 'Enter message: ' is displayed. Host and client can enter message now. 
	3.7 To disconnect, enter 'exit'.

		



Reference:

UDP socket
https://pythontic.com/modules/socket/udp-client-server-example
RC4
https://github.com/manojpandey/rc4/blob/master/rc4-3.py
RSA
https://basseltech.com/watch?v=txz8wYLITGk&i=1