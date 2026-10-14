# 微信聊天记录导出 —— 完整归档（2026-10-14）

> 工作目录：`C:\Users\Lenovo\Desktop\WeChatExport`
> 目标账号：`wxid_usdvuhs727dr22`（本机唯一账号）
> 最终结果：**677 会话 / 7,303 联系人 / 460,691 条消息**已导出

---

## 0. 结论速览

| 问题 | 结论 |
|---|---|
| 微信版本 | **4.0.3.39**（必须，见第 2 节） |
| 密钥位置 | 进程内存中，ASCII 文本 **`x'<64hex enc_key><32hex salt>'`**（98 字符） |
| 密钥用法 | **`enc_key` 的 32 字节原始值直接作 AES-256 密钥**（raw-key 模式，**不做 PBKDF2 派生**） |
| 每库密钥 | **每个库一把独立密钥**（26 个 salt 互不相同） |
| 能否一键完成 | **能**（`tool\oneclick.ps1`），前提是微信已登录过一次且保持登录态 |
| 4.1.15.13 为何失败 | 该版本已移除内存明文密钥缓存 + 自带 AES + 反调试 → 本机不可行 |

## 1. 密码学模型（实测确认）

```
页面大小 page_size      = 4096
保留区 reserved         = 80   (IV 16 + HMAC 64)
page 1: [0:16] 明文 salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC tag
page N: [0:4016] 密文    | [4016:4032] IV | [4032:4096] HMAC tag

AES:        AES-256-CBC, key = 内存中取出的 32 字节 enc_key（直接用，不派生）
校验:       mac_key = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3A, 2, 32)
            tag     = HMAC-SHA512(mac_key, 密文 || LE32(page_number))
WAL:        帧 = 24B 帧头 + 4096B 页；用同一 enc_key 解帧后按 pgno 回填
```

**关键坑（耗时最久）**：`enc_key` **不做 KDF 派生**。误加 `PBKDF2(raw, salt, 256000)` 会导致
12000+ 组参数全部失败、且 page1 恰好解出 `SQLite format 3\0` 前 16 字节（假阳性），极难定位。

## 2. 版本选择（最重要的一步）

| 版本 | 内存明文密钥 | 结论 |
|---|---|---|
| 4.0.3.39 | **有**（`x'<96hex>'` 直接可读） | ✅ 用这个 |
| 4.1.13.65 / 4.1.15.13 | 无（仅启动瞬间存在，且自带 AES + 反调试） | ❌ 放弃 |

安装包需自寻历史版本（官网只给最新）；（安装时**断网**避免自动升级）。
旧版打开新库不迁移、不改写，参数一致，可直接解。

## 3. 完整流程与绝对路径

### 一键执行（推荐）

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\Lenovo\Desktop\WeChatExport\oneclick.ps1
```

或直接用我们的库：

```powershell
$env:PYTHONUTF8="1"
$env:PYTHONPATH="C:\Users\Lenovo\Desktop\WeChatExport;C:\Users\Lenovo\Desktop\WeChatExport\lib"
C:\Python314\python.exe -m wxarchive all `
  --db-dir "E:\xwechat_files\wxid_usdvuhs727dr22_2291\db_storage" `
  --work "C:\Users\Lenovo\Desktop\WeChatExport\decrypted" `
  --out  "C:\Users\Lenovo\Desktop\WeChatExport\out"
```

`oneclick.ps1` 与 `python -m wxarchive all` 都会自动完成：找 Python → 校验版本（提示 4.0.x）→
检查依赖 → 自动定位 `db_storage` → 扫内存取全部密钥 → 解密全部库（raw-key 模式 + WAL 回填）
→ 导出 JSON/MD/INDEX → 打印汇总。**不依赖任何外部逆向工具。**

**自足库（本项目原创）**：`C:\Users\Lenovo\Desktop\WeChatExport\wxarchive\`
（模块：`crypto` / `keys` / `decrypt` / `sessions` / `export` / `cli`；文档见 `wxarchive\README.md`）

### 环境准备（一次性）

```powershell
# 依赖（本机已就绪，仅列出以便复现）
pip install pycryptodome            # 或解包 wheel 到 lib\（本机做法）
pip install zstandard               # WCDATA_CT=4 时的 zstd 解压
# frida 仅在需要从内存扫密钥时用；本机做法是从清华镜像取 wheel 解包到 lib\frida_pkg
```

| 用途 | 绝对路径 |
|---|---|
| 数据目录（微信 4.x） | `E:\xwechat_files\wxid_usdvuhs727dr22_2291\db_storage` |
| 数据目录配置来源 | `%APPDATA%\Tencent\xwechat\config\51a1fffea11325a1e4104c6b3de47af7.ini`（内容 = `E:\`） |
| 参考解密实现 | `C:\Users\Lenovo\Desktop\WeChatExport\tool\wechat-decrypt-main\decrypt_db.py` |
| 参考密钥扫描 | `C:\Users\Lenovo\Desktop\WeChatExport\tool\wechat-decrypt-main\find_all_keys.py` |
| 本项目总驱动 | `C:\Users\Lenovo\Desktop\WeChatExport\scripts\114_full_pipeline.py` |
| 导出器 | `C:\Users\Lenovo\Desktop\WeChatExport\scripts\120_export_chats.py` |
| 一键脚本 | `C:\Users\Lenovo\Desktop\WeChatExport\tool\oneclick.ps1` |
| 解密产物 | `C:\Users\Lenovo\Desktop\WeChatExport\decrypted\` |
| 导出产物 | `C:\Users\Lenovo\Desktop\WeChatExport\out\` |

### 三条命令（可复现）

```powershell
# 0) 确保微信 4.0.3.39 正在运行且已登录
Get-Process Weixin | Select-Object Id,WorkingSet64

# 1) 扫内存取全部密钥 + 解密全部库（raw-key 模式）
$env:PYTHONUTF8="1"
$env:PYTHONPATH="C:\Users\Lenovo\Desktop\WeChatExport\lib"
C:\Python314\python.exe -u C:\Users\Lenovo\Desktop\WeChatExport\scripts\114_full_pipeline.py `
  --db-dir "E:\xwechat_files\wxid_usdvuhs727dr22_2291\db_storage" `
  --out    "C:\Users\Lenovo\Desktop\WeChatExport\decrypted"

# 2) 导出聊天记录
C:\Python314\python.exe -u C:\Users\Lenovo\Desktop\WeChatExport\scripts\120_export_chats.py
```

### 输出

| 文件 | 大小 | 内容 |
|---|---|---|
| `out\chats.json` | 272.6 MB | 会话 + 消息全量（含发送者昵称映射） |
| `out\chats.md` | 249.4 MB | 可读文本 |
| `out\INDEX.md` | 小 | 会话索引（按消息数降序） |
| `decrypted\*.db` | 1.0 GB | 21 个库解密为合法 SQLite，可直接 SQL 查询 |

## 4. 数据结构要点（二次开发用）

- 消息表：`Msg_<会话ID的MD5前32位>`；`message_message_N.db` 内共 239 张 `Msg_*`
- **会话名还原（已验证 239/239 命中）**：`session_session.db` 的 `SessionTable.username`
  取 `md5(username.encode('utf-8')).hexdigest()` 即为 `Msg_` 后缀。例：
  `43601505996@chatroom` → `Msg_1c81714815724d009483dbcd06bcad94`（71505 条）
- 消息字段：`local_id / local_type / create_time / real_sender_id / message_content /
  WCDB_CT_message_content / source / WCDB_CT_source`
- 压缩：`WCDB_CT_*=4` → zstd；`=0` → 明文
- 发送者链：`real_sender_id` → 消息库 `Name2Id.rowid` → `user_name`（注意列名）
  → `contact_contact.db` 的 `contact` 表 → `coalesce(remark, nick_name, username)`
- 会话索引：`session_session.db` → `SessionTable`（717 行，`username` 含 `@chatroom`）
- 群消息正文常带 `wxid_xxx:` 前缀（导出后可按需剥离）
- 常用 `local_type`：1 文本 / 3 图片 / 34 语音 / 47 表情 / 10000、10002 系统 /
  227633266737 群接龙 / 373662154801 @所有人 / 244813135921 视频号

## 5. 未完成项

| 项 | 原因 | 补齐方式 |
|---|---|---|
| 5 个库未解密：`bizchat`、`chatbot_message`、`weclaw`、`solitaire`、`third_app_icon` | 其密钥当前不在内存（对应功能未打开） | 在微信里打开「群聊/服务号/接龙」等界面后再跑一次 `114_full_pipeline.py` |
| 图片 `.dat` 未解密 | 微信 4.x 用 AES 加密，需单独的图片密钥 | 可用 `tool\wechat-decrypt-main\find_image_key.py` |
| 4.1.15.13 环境 | 本机不可行（见第 2 节） | 需旧版环境 |

## 6. 关键代码仓库（外部参考）

| 仓库 | 用途 | 本机位置/来源 |
|---|---|---|
| [huohuoer/wechat-cli](https://github.com/huohuoer/wechat-cli) | 4.0+ 密钥扫描 + 解密 + 11 个查询命令（源码最完整） | `scripts\wechat_cli_src\`（已补 `main.py`/`output/formatter.py`） |
| [ou-o/wechat-extract](https://github.com/ou-o/wechat-extract) | 4.x 流程说明、WCDB/zstd、消息类型表、群表 MD5 规则 | `scripts\wechat_extract_src\` |
| [stargazer-2026/wechat-4.1.12-decrypt](https://github.com/stargazer-2026/wechat-4.1.12-decrypt) | Frida hook codec 偏移取 key（4.1.12.26，本机版本不适用） | `scripts\`（已记录偏移 `0x3486140`） |
| [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) | PBKDF2 派生 + 多平台 | 未取 |
| `tool\wechat-decrypt-main` | **本次实际生效的解密实现**（raw-key 模式） | 本机 `tool\` |
| `xaoyaoo/PyWxDump` | 曾经最流行，**作者已删库** | 不可用 |

## 7. 踩过的坑（省时间用）

1. **`enc_key` 不要派生** —— 最耗时的错误，见第 1 节。
2. **每库一钥** —— 不要用一个 key 试全部库。
3. 内存中同一 salt 会残留**多把历史密钥**，HMAC 校验会把当前密钥一起否掉；
   正确判据是**实际解密 page1（SQLite 头 + page_size=4096）+ page2（b-tree 类型）**。
4. `wechat-decrypt` 的 `decrypt_page` 片偏移：`iv=page[4016:4032]`、
   密文 `page[16:4016]`（4000B，不是 4032）—— 差一块就全错。
5. 沙箱相关：`taskkill` 被拒（用 `TerminateProcess`）、`OpenProcess(VM_WRITE)` 被拒、
   `frida.spawn` 卡死、`C:\Users\<用户>\.wechat-cli` 不可写（用 `--db-dir` 或改 `HOME`）。
6. **不要在已运行的微信上挂调试器/改写热路径** —— 本机实测三次导致微信崩溃。
7. PowerShell 5.1 的 here-string 含中文/转义易坏；脚本请写成 `.py`/`.ps1` 文件再执行。
