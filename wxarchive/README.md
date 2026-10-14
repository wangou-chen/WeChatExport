# wxarchive

微信 **4.0.x** 本地聊天记录导出库 —— **自足实现，不依赖任何外部逆向工具**。
在本机（Windows / 微信 **4.0.3.39**）实测完成：**677 会话 / 7,303 联系人 / 460,691 条消息** → JSON + Markdown。

> 适用版本：微信 Windows **4.0.x**（本机验证 4.0.3.39）
> **4.1.13 及以上不适用**：该区间微信已移除内存中的明文密钥缓存，并引入自带 AES + 反调试（本机实测无法取密钥）。

---

## 1. 安装

```powershell
# 方式 A：直接使用（把本目录放入 PYTHONPATH）
$env:PYTHONPATH = "<项目根>;<项目根>\lib"

# 方式 B：安装为包（会注册 wxarchive 命令）
pip install -e <项目根>
```

依赖：`pycryptodome`（必需）、`zstandard`（消息压缩必需）。Windows 自带 `ctypes`，无需 `frida`。

## 2. 一键使用

```powershell
$env:PYTHONUTF8 = "1"
$env:PYTHONPATH = "<项目根>;<项目根>\lib"
python -m wxarchive all `
  --db-dir "<数据盘>\xwechat_files\<你的wxid>_<后缀>\db_storage" `
  --work   "<项目根>\decrypted" `
  --out    "<项目根>\out"
```

`--db-dir` 可省略（自动读 `%APPDATA%\Tencent\xwechat\config\*.ini` 定位盘符）。

**前提**：微信正在运行且已登录过（保持登录态即可，重启无需扫码；密钥全程驻留内存）。

产物：

| 文件 | 说明 |
|---|---|
| `out\chats.json` | 全量结构化：会话 + 消息 + 联系人 + 会话名/user_name 映射 |
| `out\chats.md` | 可读文本（`时间 + 发送者 + 内容`） |
| `out\INDEX.md` | 会话索引（按消息数降序） |
| `out\all_keys.json` | `库路径 → {enc_key, salt}`（下次可复用，跳过扫内存） |
| `decrypted\*.db` | 标准 SQLite，可直接用任意 SQL 工具查询 |

## 3. 子命令

| 命令 | 作用 |
|---|---|
| `python -m wxarchive info` | 打印微信进程、数据目录、依赖状态 |
| `python -m wxarchive keys` | 只扫内存取密钥 → `out\all_keys.json` |
| `python -m wxarchive decrypt` | 只解密（自动复用 `all_keys.json`） |
| `python -m wxarchive export` | 只导出全部（需已解密）；`--limit N`、`--keep-group-prefix` |
| `python -m wxarchive sessions --limit 30` | 列出会话（需已解密） |
| **`python -m wxarchive chat --list`** | 列出全部会话标识（username / 显示名 / 消息表） |
| **`python -m wxarchive chat --chat <标识>`** | **按单一用户/群导出** |
| `python -m wxarchive all` | 一键：解密 + 导出全部 |

### 3.1 按单一用户导出

```powershell
# 先看有哪些会话可选
python -m wxarchive chat --list --work .\decrypted

# 按显示名（支持子串）
python -m wxarchive chat --chat "翔铭"   --work .\decrypted --out .\out\single
python -m wxarchive chat --chat "pubg"   --work .\decrypted --out .\out\single

# 按 username
python -m wxarchive chat --chat "<群ID>@chatroom" --work .\decrypted --out .\out\single
python -m wxarchive chat --chat "<某联系人的wxid>"  --work .\decrypted --out .\out\single

# 按消息表名或其 hash
python -m wxarchive chat --chat "Msg_4bd000a41580553ff94c8a591518a505" --work .\decrypted --out .\out\single

# 只要最近 500 条
python -m wxarchive chat --chat "pubg" --limit 500 --work .\decrypted --out .\out\single
```

产物：`out\single\chat_<显示名>.json` 与 `chat_<显示名>.md`（单文件，含时间/发送者/内容）。

**匹配规则**：`--chat` 依次尝试
① 精确等于 username（`wxid_*` / `*@chatroom` / `gh_*`）→
② 精确等于显示名（备注/昵称）→ ③ 子串匹配 username / 显示名 / 表 hash → ④ 直接给 `Msg_<32hex>`。
同名可能有多个（不同群同名），此时会一并导出并在同一文件内分节。

> **重要**：微信把**同一个会话的消息表分片存放在 `message_0/1/2/3.db`**。
> 本工具会**自动合并四个分片、按时间排序、去除重复**（实测 `翔铭`：4 分片 579+531+240+124 → 合并 1473 条，
> 时间跨度 2024-02-24 ~ 2026-10-14）。不要用「单库查询」的结果当作该用户全部记录。


## 4. 技术结论（本库据此实现，均为实测）

### 4.1 密钥

| 项 | 值 |
|---|---|
| 位置 | 进程内存（`Weixin.exe`） |
| 形式 | ASCII 文本 `x'<64hex enc_key><32hex salt>'`，98 字符 |
| 用法 | **`enc_key` 的 32 字节原值直接作 AES-256 密钥**（raw-key 模式，**不做 KDF 派生**） |
| 粒度 | **每库一把独立密钥**（26 个 salt 互不相同） |

> **最大坑**：若对 `enc_key` 多做一次 `PBKDF2(raw, salt, 256000)` 派生，则所有页解密失败，
> 但 page1 仍会"恰好"解出 `SQLite format 3\0` 前 16 字节（假阳性），极难定位。
> 本库的 `crypto.check_key()` 用 **page_size 字段 + page2 b-tree 类型** 双判据规避此坑。

### 4.2 页布局

```
page_size = 4096,  reserved = 80 (IV 16 + HMAC 64)
page1 = [0:16] 明文 salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC tag
pageN = [0:4016] 密文    | [4016:4032] IV | [4032:4096] HMAC tag

AES:  AES-256-CBC, key = enc_key（直接使用）
校验: mac_key = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3A, 2, 32)
      tag     = HMAC-SHA512(mac_key, 密文 || LE32(page_number))
WAL:  帧 = 24B 帧头 + 4096B 页，用同一 enc_key 解密后按 pgno 回填
```

密文区间易错点：page1 是 `[16:4016]`（4000 B），**不是** `[16:4032]`。

### 4.3 数据映射

- 消息表：`Msg_<md5(SessionTable.username)>`（**239/239 实测命中**）
- 发送者链：`real_sender_id` → 消息库 `Name2Id.rowid` → `user_name`（注意列名）
  → `contact_contact.db.contact` → `coalesce(remark, nick_name, username)`
- 内容：优先 `message_content`（`WCDB_CT_message_content == 4` 为 zstd），降级 `source`（XML）
- 群聊正文常带 `wxid_xxx:` 前缀，默认剥离（`--keep-group-prefix` 可保留）

## 5. 用 SQL 直接查解密后的库

```python
import sqlite3
con = sqlite3.connect("file:decrypted/message_message_0.db?mode=ro", uri=True)
con.text_factory = lambda b: b.decode("utf-8", "replace")
print(con.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone())
```

## 6. 目录结构

```
wxarchive/
├── __init__.py     版本与概述
├── __main__.py     python -m wxarchive 入口
├── cli.py          命令行（info/keys/decrypt/export/sessions/all）
├── crypto.py       SQLCipher4 页解密 + WAL 回填 + 密钥判定
├── keys.py         进程内存扫密钥（ctypes）
├── decrypt.py      数据目录探测 + 批量解密
├── sessions.py     会话/联系人/Name2Id 映射
└── export.py       导出 JSON / Markdown / INDEX
pyproject.toml
```

## 7. 限制与未覆盖

| 项 | 说明 |
|---|---|
| 微信 4.1.13+ | 不支持（内存无明文密钥 + 反调试），需 4.0.x 环境 |
| **必须阻断自动更新** | 见第 8 节：微信一旦升到 4.1.13+，本库将永久失效 |
| 图片 `.dat` | 微信 4.x 用独立 AES 密钥，本库未实现（需另取图片密钥） |
| 视频/语音/文件 | 仅导出元数据与路径，未搬运媒体文件 |
| 未打开的库 | 若某库当前未被微信打开，其密钥不在内存 → 该库无密钥；打开对应界面（朋友圈/收藏/群聊）后再跑一次即可 |
| 非 Windows | 内存扫描用 ctypes/Win32 API，仅 Windows |

## 8. 阻断微信自动更新（**必做**）

微信 4.1.13+ 移除了内存明文密钥，**一旦自动升级，本库立即失效且无法回退取密钥**。

本机实测的更新机制：

| 项 | 值 |
|---|---|
| 更新器 | `<安装目录>\<版本>\WeixinUpdate.exe` |
| 更新日志 | `%APPDATA%\Tencent\xwechat\log\update_*.xlog`（持续写入 = 反复检查更新） |
| 自启项 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Weixin` = `"...\Weixin.exe" -autorun` |
| 计划任务 / 服务 | 无（更新由微信进程自行发起） |

阻断工具（**需管理员**，可回滚）：

```powershell
# 预览（不做任何改动）
powershell -ExecutionPolicy Bypass -File <项目根>\block_weixin_update.ps1

# 执行：防火墙封更新器 + hosts 封下载域 + 删自启项 + 更新器改名
powershell -ExecutionPolicy Bypass -File <项目根>\block_weixin_update.ps1 -Apply -RenameUpdater

# 回滚
powershell -ExecutionPolicy Bypass -File <项目根>\block_weixin_update.ps1 -Restore
```

四层阻断（各自独立生效，按可靠性排序）：

1. **防火墙出站规则**（`wxarchive-block-weixin-update`）按程序阻断 `WeixinUpdate.exe` —— 最可靠；
2. **hosts 黑洞**：`dldir1.qq.com`、`dldir1v6.qq.com`、`dldir2.qq.com`、`dldir3.qq.com`、`dl.qq.com`、
   `up.qq.com`、`update.qq.com`、`update.weixin.qq.com`、`cdn.update.weixin.qq.com` → `127.0.0.1`；
   *只封下载域，不封 `weixin.qq.com` / `servicewechat.com`，避免小程序与功能异常*；
3. **删除自启项** `HKCU\...\Run\Weixin`（减少启动即检查更新的机会，原值已备份）；
4. **更新器改名**（`-RenameUpdater`）：`WeixinUpdate.exe` → `.exe.disabled`。

> 若升级提示仍出现，说明微信走了其它分发域名：用
> `Get-NetTCPConnection -OwningProcess <Weixin pid>` 观察对端再补 hosts 条目。
