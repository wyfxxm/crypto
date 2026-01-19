# SM2 实现

本目录提供基于 C 的 SM2 实现，包含：

- **密钥生成**：`sm2_generate_key`
- **签名 / 验签**：`sm2_sign` / `sm2_verify`
- **加密 / 解密**：`sm2_encrypt` / `sm2_decrypt`
- **自实现大数运算**：`sm2_bn.c/h`
- **SM3 哈希**：`sm3.c/h`（用于 KDF 与加密校验）

## 目录结构

- `sm2.h` / `sm2.c`：SM2 主逻辑（曲线运算、签名、验签、加解密）
- `sm2_bn.h` / `sm2_bn.c`：256 位大数基础运算
- `sm3.h` / `sm3.c`：SM3 哈希实现

## 说明

1. **签名/验签输入**：`sm2_sign` / `sm2_verify` 直接接收 32 字节摘要 `e`。
2. **加解密输出格式**：`C1 || C3 || C2`（`C1` 为未压缩点 65 字节）。
3. **随机数来源**：优先读取 `/dev/urandom`，不可用时退化到 `rand()`。

## 编译示例

```bash
gcc -O2 -Wall -Wextra -c sm2.c sm2_bn.c sm3.c
```
