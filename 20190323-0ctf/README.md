# 0CTF/TCTF 2019 Quals Writeup

## vim

### 题目背景

1. 实现了 vim 的第四种加密解密方式，运用了 `vimcrypt` 功能。在 vim 打开时如果以 `VimCrypt~0_` （下划线为 0 到 3 的数字，表示不同的加密）时会自动调用解密，正常情况会询问密钥，在题目中被固定了。

### 关键位置

1. 在解密过程计算中，存在类似 `(idx + step) % size` 的运算来计算下一个赋值的位置， `step` 可控导致可以整数溢出。（溢出后取模依然为负数）
2. 以 `idx >= 0` 开始为写入内容，所以需要在溢出后使得其 `>= 0` 来赋值需要写入的内容。这里需要考虑到再逐字节下溢时，可以覆盖到最高位（符号位），导致 `idx` 变为正值再逐步减小。
3. 写入时 got 表可写，但是由于题目在用 vim 打开文件后就关闭，vim 为 tui 程序，无法使用正常 stdin 和 stdout ，需要找一个合适的 gadget 来 `cat flag` 并且输出。

## lua 沙箱

### 题目背景

1. lua 5.0.3 沙箱，保留了 `loadstring` 功能，删除了文件访问和 execute one gadget.

### 关键位置

1. lua 5.0 在加载时相比 5.1 更加严格，存在字节码校验，使用了 "symbexec" （符号执行？），其实就是计算了各种 size ，保证了指令执行的时候用到的数值对应的栈、常量表索引均不会越界。
2. 然而对比 check 和 vm 中的执行过程，可以找到一条指令没有进行校验，用该指令加载字符串作为对象（越界）即可。
3. 堆风水 TBC.

## babyaegis

### 题目背景

1. 题目开启了 address sanitizer
2. delete 函数可存在 UAF

### 关键位置
1. secret 函数写一个地方为0
2. 通过一些操作，制造出一个 UAF
3. 利用 uaf 进行任意地址读写
4. __sanitizer::Die()函数内部call rax 可挟持程序流程 



## babyheap

### 题目背景

1. 题目实现了一个简单的堆分配，有Allocate，Update，Delete，View四个功能
2. 题目限制了堆块大小只能是0x00 - 0x58

### 关键位置

1. 题目漏洞在于Update中，存在着一个null off by one，但是这里没有unsorted bin，而想要unsorted bin需要触发malloc_consolidate来让多余的fast bin合并成unsorted bin，这一第一个问题就是，top比较大，很难触发malloc_consolidate，解决思路：利用null off by one来缩小top chunk，当top小到无法满足分配的时候，就会触发malloc_consolidate。
2. 由于是libc 2.28的库，在null off by one攻击之后，可以使堆块重叠，如何获取shell是一个难题，在libc 2.28中，io vtable被废，所以劫持unsorted bin没有作用，而又不能申请0x60的块，这样无法直接分配到malloc hook位置，解决方案，任然选择利用fastbin attack，这里利用堆块高位0x55和0x53来最为合法的size，直接分配堆块到main arena，而top的指针就在fastbin下面，这样可以修改top指针，指向某个合法的位置，达到任意内存分配。
3. 这里利用思路一般直接改malloc hook 到one gadget，但是这题所有的one gadget都不行，所以有两种利用思路
4. 第一个是修改top到free hook上方，虽然比较远，但是可以分配到free hook的位置
5. 第二个是修改malloc hook到call realloc的位置调用realloc，然后修改realloc hook到one gadget这样就可以触发one gadget了，而realloc hook就在malloc hook - 0x8的位置，所以可以两个一起改。
