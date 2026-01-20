# Crypto 算法实现

本仓库提供基于 C 的 RSA、SM2、SM3、SM4 以及大数运算实现。所有源码已合并到仓库根目录。

## RSA

- **密钥生成**：`rsa_generate_key`
- **公钥运算**：`rsa_public`（模幂运算）
- **私钥运算**：`rsa_private`（CRT 运算）
- **字节封装**：`rsa_public_bytes` / `rsa_private_bytes`（公私钥与输入输出使用 `uint8_t`）
- **大数运算**：复用 `crypto_bn.c/h`

### 说明

1. **密钥生成**：使用 Miller-Rabin 生成素数，默认公钥指数为 65537。
2. **私钥格式**：包含 `n`、`d`、`p`、`q`、`dp`、`dq`、`qinv` 共 7 个大整数。
3. **输入输出**：`rsa_public` / `rsa_private` 接受 `crypto_bn`，内部会对输入取模 `n`。
4. **字节接口**：`rsa_public_bytes` / `rsa_private_bytes` 使用 `rsa_public_key_bytes` / `rsa_private_key_bytes` 传递大整数，并按模长输出字节结果。
5. **随机数来源**：优先读取 `/dev/urandom`，不可用时退化到 `rand()`。

## SM2

- **密钥生成**：`sm2_generate_key`
- **签名 / 验签**：`sm2_sign` / `sm2_verify`
- **加密 / 解密**：`sm2_encrypt` / `sm2_decrypt`
- **大数运算**：复用 `crypto_bn.c/h`
- **SM3 哈希**：`sm3.c/h`（用于 KDF 与加密校验）

### 说明

1. **签名/验签输入**：`sm2_sign` / `sm2_verify` 直接接收 32 字节摘要 `e`。
2. **加解密输出格式**：`C1 || C3 || C2`（`C1` 为未压缩点 65 字节）。
3. **随机数来源**：优先读取 `/dev/urandom`，不可用时退化到 `rand()`。

## SM4

### 性能优化依据

1. **T-Table 合并 S 盒与线性变换 L / L'**
   - 将 `τ`(S 盒) 与 `L`/`L'` 组合为 4 组 256 项查表（按字节位置展开），将每轮的非线性 + 线性变换从多次位运算/旋转压缩为 4 次查表 + 3 次异或。
   - 对加密轮函数与轮密钥扩展分别使用 `L` 与 `L'` 的表，避免在关键路径里频繁调用旋转与组合操作。

2. **轮函数展开（4 轮一组）+ 寄存器滚动状态**
   - 用 `x0..x3` 滚动保存状态，避免 36 字数组读写带来的内存访问与边界检查。
   - 4 轮为一组展开，减少循环控制分支与索引开销，改善指令流水与分支预测。

3. **一次性初始化查表**
   - 查表在首次调用时构建，后续所有密钥扩展与加解密复用，避免每次重复预计算。

上述优化将 SM4 轮函数的关键路径从“字节替换 + 多次旋转 + 多次数组访问”压缩为“查表 + 异或 + 少量寄存器操作”，在常见编译器优化级别下能显著提升吞吐。

## 编译示例

```bash
gcc -O2 -Wall -Wextra -c rsa.c crypto_bn.c
```

```bash
gcc -O2 -Wall -Wextra -c sm2.c sm3.c crypto_bn.c
```
