## ropme (BSIDESSF2021)

I didn't really participate in the ctf, but I found this challenge to be
interesting and since not many teams solved it/posted writeups I decided to
post my solution. It's probably not the most elegant - if you solved it in a
different way I'd love to hear about it.

In this writeup, I'm assuming you have a basic understanding of x86 architecture,
return oriented programming, and the Linux API.

## Exploitable Service

We're given a service binary and its source code.

```
[joey@gibson]$ file ropme
ropme: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b82649cdb66e4b3f92ea5fd28e374b5793cb9f26, not stripped
```

The target binary is a 32-bit ELF. This will be useful when we are writing our
exploit. Let's take a look at the important parts of the source code.

```
// Generate a random block of +rwx memory that'll be filled randomly
uint32_t *random_code = mmap((void*)CODE_START,  CODE_LENGTH,  PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

// Allocate memory for the user to send us a stack - it's just +rw
uint8_t  *stack       = mmap((void*)STACK_START, STACK_LENGTH, PROT_READ | PROT_WRITE,             MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

...

alarm(TIME);

// Set the randomness in stone at the outset
time_t t = time(NULL);

// Immediately let the user know how much time they have
printf("The current time is: %ld\n", t);
printf("You have %d seconds to make this work\n", TIME);

// Populate the random code block using a predictable RNG
int i;
srand(t);
for(i = 0; i < CODE_LENGTH / 4; i++) {
    random_code[i] = rand();
}

```
Looks like the service allocates two memory regions:
    - `random_code` with read, write, and exec permissions at address
      `CODE_START` (`0x13370000`).
    - `stack` with just read and write permissions and an address chosen by the
      system (`STACK_LENGTH` is `NULL`).

The program then uses `time(2)` to generate the seed for pseudo-random number
generation and conveniently tells the client what that seed is. It proceeds to
fill `random_code` memory region with (you guessed it!) pseudo-random 32-bit
numbers.

Finally the service reads `STACK_LENGTH` bytes of user input into the `stack`
region, uses `asm(3)` to clear all of the registers, set the stack pointer
(`$esp`) to the `stack` memory region and immediately `ret`'s.

What's going on here? Essentially, a contrived example of a stack overflow
vulnerability, exploitable via Return Oriented Programming (ROP). Instead of
writing a vulnerable program, the author of this challenge cut to the chase
and generated an artificial stack for our exploit. The first thing that happens
after we populate that stack is the `ret` operation, so we already control the
instruction pointer (`$eip`) with the first four bytes of our input.

## Dumpster diving for gadgets

We control `$eip` but the only place we can reliably jump to is the `random_code`
memory region, filled with junk. Lots of interesting things can be found in the
junk!

Turns out if you generate `0x500000` of pseudo-random bytes, *some* of those
bytes will happen to be ROP gadgets. Remember that we are handed over the seed
for pseudo-random number generation, which means we can re-create `random_code`
locally (even if we weren't handed the seed - one second is a *long* time - we
could call `time(2)` locally and get the same result).

The plan for the exploitation is straightforward - generate the same random
memory that the service did and find the necessary gadgets for our ROP chain.
There's only one problem - our ROP gadgets can't be too long. The longer
the instruction the less chances we have of finding it in the randomly
initialized memory.

What happens if not all gadgets are present? We just try again! I wrapped my
exploit with a shell script that kept trying until the exploit was successful.
Through trial and error I found that we can find any two-byte gadget (including
`ret`) with every attempt. A three-byte gadget already calls for some
bruteforcing, so we must keep those to a minimum (my rop chain ended up having
two three-byte gadgets - I bet there's a better solution out there).

## Exploit methodology

The goal of this challenge is to read the contents of `/home/ctf/flag.txt`. As
is often the case with restricted exploitation environment, instead of attacking
this problem head-on, we will modify the environment to make exploitation
easier for us. We have full control over the stack, but it is set as
non-executable. We will use a ROP chain to change the stack memory region
permissions to executable. Then we simply jump into the stack and execute the
shellcode that will read the flag for us.

To change permissions of a memory region, we utilize the `mprotect(2)` system
call. If you've read the man page you know that `mprotect` might expect a
page-aligned address and length (more often than not this is true). Since we
don't know the stack address, the first thing our ROP chain needs to do is grab
the stack address from the stack pointer. As this is our first operation, `esp`
will be pointing at `stack+4`, so we decrement `ebx` four times. Now we pop the
rest of the arguments and the syscall number to the respective registers and run
`int 0x80` (remember we're dealing with a 32-bit system).

Upon returning from `mprotect` we should be able to jump to `esp`. There's a
caveat. The calling convention uses the stack for arguments, but we're already
using the stack for our code. We need a new stack! Seems obvious, but I took
that for granted and spent an hour wondering why my exploit was coring.
Fortunately, we can just use `random_code` segment as our new stack. The first
order of business in our second stage shellcode will be to move an address in
`random_code` into `esp`. Besides that it's just a vanilla `execve` shellcode
that's going to cat the flag.

Let's see the exploit in action:

```
[joey@gibson]$ ./exploit
=== Generating random memory with seed 1615121940
...
=!!= Found EBX mov gadget @ 0x135e533c
=!!= Found INT 0x80 gadget @ 0x1385c0c8
=-= All gadgets are present! Sending the exploit..
CTF{bounce_bounce_bounce}
```


