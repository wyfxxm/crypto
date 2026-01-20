# RSA 实现

本目录提供基于 C 的 RSA 实现，包含：

- **密钥生成**：`rsa_generate_key`
- **公钥运算**：`rsa_public`（模幂运算）
- **私钥运算**：`rsa_private`（模幂运算）
- **大数运算**：复用 `bn/crypto_bn.c/h`

## 目录结构

- `rsa.h` / `rsa.c`：RSA 主逻辑（密钥生成、公钥/私钥模幂运算）

## 说明

1. **密钥生成**：使用 Miller-Rabin 生成素数，默认公钥指数为 65537。
2. **输入输出**：`rsa_public` / `rsa_private` 接受 `crypto_bn`，内部会对输入取模 `n`。
3. **随机数来源**：优先读取 `/dev/urandom`，不可用时退化到 `rand()`。

## 编译示例

```bash
gcc -O2 -Wall -Wextra -I../bn -c rsa.c ../bn/crypto_bn.c
```
