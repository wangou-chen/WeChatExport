# scripts/_archive —— 调查过程归档（仅供追溯，非运行依赖）

这 60 个脚本是**调查「如何取得微信 4.0.x 数据库密钥」过程中产生的完整技术档案**。
它们记录了我们排除过的每一条路径及其原因，可用于：

- 复核「为什么 4.1.13+ 不可行」的实测证据；
- 在新环境重现某个具体诊断；
- 未来版本变化时，快速复用某条思路。

> ⚠️ **这些脚本不再是工具的组成部分，且多数需要特定前置条件**（微信运行中 / 管理员 / 特定版本）。
> 正常运行工具**只需** `wxarchive/` 包 + `scripts/` 根目录下的 15 个脚本。
> 部分脚本（尤其 `70–89` 区间的调试器/硬件断点方案）**实测会导致微信崩溃**，请勿在正常使用时执行。

## 按主题索引

| 编号 | 主题 | 代表脚本 |
|---|---|---|
| `20–21` | 初版解密器/导出器（后被 `wxarchive` 取代） | `20_decrypt.py`、`21_export.py` |
| `40–52` | Frida 注入、bcrypt hook、PE 导入表分析、AES 代码定位 | `41_frida_aeskeys.py`、`42_iat_scan.py`、`52_find_aes.py` |
| `60–61` | 内存与文件级密钥扫描（证明密钥不在内存/文件的常规形态中） | `60_hexscan_all.py`、`61_filescan_keys.py` |
| `70–94` | **启动期截获尝试**：CreateProcess 门控、挂起启动、硬件断点、AES-NI 定位、codec 函数定位 | `75_suspended_multihook.py`、`89_hwbreak_keyexp.py`、`93_dump_aes256_region.py` |
| `95–99` | 多进程内存扫描、密钥串上下文读取、明文 SQLite 搜索 | `95_memscan_mp.py`、`99_grab_all_keys.py` |
| `101–113` | **参数标定与逐项排除**（KDF 迭代/PRF/页大小/布局/密文区间/IV 位置） | `109_exhaustive_layout.py`、`112_scan_pagesize.py` |
| `96`, `98` | 辅助查询（key_info.db 读取、明文 SQLite 搜索） | `96_read_keyinfo.py`、`98_find_plain_sqlite.py` |

## 关键负面结论（这些脚本产出的证据）

1. **4.1.13+ 内存中无 `x'<hex>'` 明文密钥**：16 进程 / 1.6 GB 扫描 0 命中（`60_hexscan_all.py`）。
2. **全进程任意偏移无 32 字节原始密钥**：stride-8 全量 2.26 亿候选 + salt 邻域 stride-1，0 命中（`95_memscan_mp.py`）。
3. **密钥不在本地文件**：125 个配置文件、`key_info.db` 284 条封装记录，均 0 命中（`61_filescan_keys.py`、`97_scan_keyinfo_blobs.py`）。
4. **不使用 Windows CNG**：`BCryptGenerateSymmetricKey/ImportKey/Decrypt/Encrypt` 运行期 0 次调用（`41_frida_aeskeys.py`、`50_frida_exportkey.py`）。
5. **该版本有反调试**：`DebugActiveProcess` + 硬件断点三次导致微信崩溃（`89_hwbreak_keyexp.py`）。
6. **正确参数只有一组**：`enc_key` 直接作 AES-256 密钥（**不做 KDF 派生**），密文区间 page1=`[16:4016)`、pageN=`[0:4016)`，IV=`[4016:4032)`（由 `101–113` 的枚举排除 + `tool/wechat-decrypt-main` 验证得出）。

## 删除说明

已删除 9 个脚本（纯粹冗余/调试残留，结论已并入文档）：
`90_diag_keysearch.py`、`90_verify_key.py`、`91_find_key.py`、`100_check_decrypted.py`、
`115_diag_scan.py`、`116_diag_114.py`、`117_debug_scan.py`、`118_check_verify.py`、`201_style_report.py`。

对应能力现由 `wxarchive` 提供：
`90_verify_key.py` → `wxarchive.crypto.check_key()`；
`100_check_decrypted.py` → `wxarchive` 解密流程自带校验；
`201_style_report.py` → `scripts/202_style_report.py`。
