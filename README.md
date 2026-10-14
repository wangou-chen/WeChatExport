# wxarchive · 微信聊天记录导出工具

从本机微信客户端提取并导出聊天记录：**内存取密钥 → SQLCipher 解密 → 结构化导出 → 表达方式分析**。
全部自足实现，不依赖任何第三方逆向工具运行时（唯一依赖 `pycryptodome` 与 `zstandard`）。

**实测环境**：Windows · 微信 **4.0.3.39 / 4.1.0.30** · Python 3.14
**实测成果**：解密 **22 个库 / 946 MB** → 导出 **412 会话 / 7,305 联系人 / 46.1 万条消息**

```powershell
# 零配置启动（无需设置 PYTHONPATH）
cd <项目根> ; python -m wxarchive all
```

---

## 1. 适用版本（最关键的一条）

| 微信版本 | 内存是否有明文密钥 | 能否使用 |
|---|---|---|
| **4.0.x**（实测 4.0.3.39） | ✅ 有 | **可用** |
| **4.1.0.x**（实测 4.1.0.30） | ✅ 有 | **可用** |
| 4.1.13 及以上（实测 4.1.13.65、4.1.15.13） | ❌ 无 | **不可用**（见 §8） |

> ⚠️ **必须先禁止微信自动更新**，否则一旦升到 4.1.13+ 就再也取不到密钥。
> 工具：`block_weixin_update_v2.ps1`（管理员运行 `-Apply`）。

## 2. 环境要求

- Windows（内存扫描使用 Win32 API + `ctypes`）
- Python **3.10+**
- `pycryptodome`（必需）、`zstandard`（消息为 zstd 压缩，必需）
- 微信正在运行且**已登录**（保持登录态即可，无需反复扫码）

```powershell
pip install pycryptodome zstandard
```

## 3. 快速开始

> **可移植 + 零配置**：本工具不含任何机器特定的硬编码路径（已全量审计）；
> 依赖缺失时会**自动回退到项目自带的 `lib/`**，因此无需手动设置 `PYTHONPATH`。

```powershell
cd <项目根>

# 一键：取密钥 → 解密全部库 → 导出全部聊天记录
python -m wxarchive all
```

**依赖**（二选一，任一即可）：

```powershell
# 方式 1：装到系统 Python（推荐，一劳永逸）
pip install pycryptodome zstandard

# 方式 2：什么都不装 —— 工具会自动使用项目自带 lib/ 内的副本
#         （lib/ 为 gitignore 排除项；若从 git clone，请用方式 1）
```

或使用一键脚本（自动定位 Python、检查依赖、提示版本；根目录自动取脚本所在目录）：

```powershell
powershell -ExecutionPolicy Bypass -File .\oneclick.ps1
```

### 常见启动报错

| 报错 | 原因 | 解决 |
|---|---|---|
| `ModuleNotFoundError: No module named 'Crypto'` | 系统未装 pycryptodome，且项目 `lib/` 被删（如 git clone 后） | `pip install pycryptodome` |
| `ModuleNotFoundError: No module named 'zstandard'` | 同上（zstd 解压消息需要） | `pip install zstandard` |
| `[错误] 未找到微信数据目录` | 微信未登录过 / 数据在非默认位置 | 用 `--db-dir`、`wxarchive.config.json` 或 `$env:WXARCHIVE_DB_DIR` |

### 路径解析优先级

| 项 | 优先级 |
|---|---|
| 数据目录 `db_storage` | `--db-dir` > 项目配置 `wxarchive.config.json` > 环境变量 `WXARCHIVE_DB_DIR` > **自动探测** |
| 解密输出目录 | `--work` > 环境变量 `WXARCHIVE_WORK` > `<当前目录>\decrypted` |
| 导出目录 | `--out` > 环境变量 `WXARCHIVE_OUT` > `<当前目录>\out` |
| 密钥缓存 | `--keys-file` > 环境变量 `WXARCHIVE_KEYS` > `<导出目录>\all_keys.json` |

> **关于「换了文件夹还是找到原来的库」**：自动探测的**探测源是微信自身的配置**
> `%APPDATA%\Tencent\xwechat\config\*.ini`（内容是数据盘符，如 `E:\`），
> 所以工具放在任何文件夹都会指向同一台机器上的同一份微信数据 —— **这是设计行为，不是硬编码**。
> 用 `python -m wxarchive info` 可看**当前数据目录及其来源**；要锁定到别处，用下面任一方式。

**方式 A：项目配置文件（推荐，随目录走）**

```powershell
# 复制模板并填写
Copy-Item .\wxarchive.config.example.json .\wxarchive.config.json
# 编辑其 db_dir / work / out 字段（留空则继续向下回退）
```

**方式 B：环境变量**

```powershell
$env:WXARCHIVE_DB_DIR = "D:\xwechat_files\your_wxid\db_storage"
python -m wxarchive all
```

**方式 C：命令行参数**

```powershell
python -m wxarchive all --db-dir "D:\xwechat_files\your_wxid\db_storage"
```

**安全行为**：以上三种「显式来源」若路径无效，程序会**直接报错退出**，绝不静默回退到别的目录。
密钥缓存也做了校验——若缓存的 salt 与当前库不符（说明是别的数据目录的缓存），会自动作废并重新扫描。

**产物**

| 路径 | 内容 |
|---|---|
| `out\chats.json` | 全量结构化：会话 + 消息 + 联系人 + 会话名映射 |
| `out\chats.md` | 可读文本（`时间 + 发送者 + 内容`） |
| `out\INDEX.md` | 会话索引（按消息数降序） |
| `out\all_keys.json` | 密钥缓存（下次跳过扫内存；**请妥善保管**） |
| `decrypted\*.db` | 标准 SQLite，可直接用任意 SQL 工具查询 |

## 4. 子命令

| 命令 | 作用 |
|---|---|
| `python -m wxarchive info` | 环境自检：微信进程 / 数据目录 / 依赖状态 |
| `python -m wxarchive keys` | 只扫内存取密钥 |
| `python -m wxarchive decrypt` | 只解密（自动复用 `all_keys.json`） |
| `python -m wxarchive export` | 只导出全部 |
| `python -m wxarchive sessions --limit 30` | 列出会话 |
| `python -m wxarchive chat --list` | 列出全部会话标识 |
| **`python -m wxarchive chat --chat <标识>`** | **按单一用户/群导出** |
| `python -m wxarchive all` | 一键：解密 + 导出 |

通用参数：`--db-dir`（数据目录，默认自动探测）、`--work`（解密目录）、`--out`（导出目录）、
`--keys-file`（密钥 JSON 路径）。

### 4.1 按单一用户导出

```powershell
python -m wxarchive chat --list                          # 先看有哪些会话
python -m wxarchive chat --chat "翔铭"                    # 按显示名（支持子串）
python -m wxarchive chat --chat "45452547735@chatroom"   # 按 username
python -m wxarchive chat --chat "Msg_4bd000a4..."        # 按消息表名
python -m wxarchive chat --chat "pubg" --limit 500        # 只要最近 500 条
```

产物：`out\single\chat_<显示名>.json` 与 `.md`。

> **重要**：微信把**同一会话的消息表分片存放在 `message_0/1/2/3.db`**。
> 本工具自动**合并四个分片 → 按时间排序 → 去重**。不要单独查询某个分片就当作全部记录。
> `export` 与 `chat` 共用同一套合并逻辑（`wxarchive/export.py::_collect_sessions`），
> 产出保证**一个会话只有一行**。若你自行逐个分片查询，会看到同一会话出现多条、
> 条数偏小（例如某群在 `message_0.db` 有 71,505 条、`message_3.db` 有 44,087 条，
> 合并去重后为 **127,136** 条）。

**字段语义**：会话对象的 `count` 是各分片**原始行数之和**，`exported` 是去重后的实际消息数，
`messages` 长度等于 `exported`。二者之差（本次全库 789 条）就是分片间的重复行，
属正常现象，不是丢数据。

### 4.2 表达方式分析

```powershell
# 生成某联系人的语体分析报告（句长/标点/语气词/口头禅/连发节奏/话题/活跃时段）
python scripts\202_style_report.py --chat "翔铭" --pronoun 他 --label 翔铭
python scripts\202_style_report.py --chat "小狗媳妇" --who "小狗媳妇 ᝰꫛꫀꪝ" --pronoun 她 --label 小狗媳妇
```

产物：`out\analysis\<名称>_表达方式分析.md` + 原始消息留档 `_<名称>_messages.txt`。

## 5. 核心技术结论（工具据此实现，均为实测）

### 5.1 密钥

| 项 | 值 |
|---|---|
| 位置 | 微信进程内存 |
| 形式 | ASCII 文本 `x'<64hex enc_key><32hex salt>'`（98 字符） |
| **用法** | **`enc_key` 的 32 字节原值直接作 AES-256 密钥**（raw-key 模式，**不做 KDF 派生**） |
| 粒度 | **每个库一把独立密钥**（26 个 salt 互不相同） |
| 稳定性 | 不随客户端升级轮换（升级到 4.1.0.30 后旧密钥仍有效） |

### 5.2 页加密布局

```
page_size = 4096,  reserved = 80 (IV 16 + HMAC 64)
page1 = [0:16] 明文 salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC tag
pageN = [0:4016] 密文    | [4016:4032] IV | [4032:4096] HMAC tag

AES:  AES-256-CBC，key = enc_key（直接使用）
校验: mac_key = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3A, 2, 32)
      tag     = HMAC-SHA512(mac_key, 密文 || LE32(page_number))
WAL:  帧 = 24B 帧头 + 4096B 页，同一 enc_key 解密后按 pgno 回填
```

### 5.3 数据映射

```
消息表 = Msg_ + md5(SessionTable.username)        （实测 239/239 命中）
发送者 = real_sender_id → 消息库 Name2Id.rowid → user_name（列名是 user_name）
        → contact.db.contact → coalesce(remark, nick_name, username)
内容   = message_content 优先（WCDB_CT_message_content == 4 为 zstd），降级 source(XML)
```

## 6. 常见坑（都是实测踩过的）

1. **不要对 `enc_key` 做 PBKDF2 派生**。这是最耗时的错误：错误派生会导致所有页解密失败，
   但 page1 仍会「恰好」解出 `SQLite format 3\0` 前 16 字节（**假阳性**），极难定位。
   正确判据是 **page_size 字段 == 4096 且 page2 首字节为 b-tree 类型**（`crypto.check_key()`）。
2. **每库一钥**，不要用一个密钥试全部库。
3. **内存中同一 salt 会残留多把历史密钥**，HMAC 校验会把当前密钥一起否掉 → 必须用实际解密判定。
4. `decrypt_page` 的密文区间：page1 是 `[16:4016]`（**4000 字节**），不是 `[16:4032]`。差一块全错。
5. **同一会话分散在 4 个分片库**，必须合并去重。
6. **不要在已运行的微信上挂调试器或改写热路径指令** —— 实测三次导致微信崩溃（该版本有反调试）。

## 7. 目录结构

```
WeChatExport/
├── wxarchive/                 ★ 自足库（核心）
│   ├── cli.py                 命令行入口（info/keys/decrypt/export/sessions/chat/all）
│   ├── crypto.py              SQLCipher4 页解密 + WAL 回填 + 密钥判定
│   ├── keys.py                进程内存扫密钥（ctypes）
│   ├── decrypt.py             数据目录探测 + 批量解密
│   ├── sessions.py            会话/联系人/Name2Id 映射
│   ├── export.py              导出 JSON / Markdown / INDEX
│   ├── _bootstrap.py          依赖自举：缺失时回退到项目 lib/
│   └── README.md              库文档
├── wxarchive.config.example.json   项目配置模板（锁定数据目录/输出目录）
├── oneclick.ps1               一键脚本（根目录自动取脚本位置）
├── block_weixin_update_v2.ps1 禁止微信自动更新（管理员，可回滚）
├── scripts/                   可用链路（15 个脚本，见 §10）
│   └── _archive/              调查过程归档（60 个，含负面结论索引 README）
├── tool/wechat-decrypt-main/  外部参考实现（解密算法的原始来源）
├── ARCHIVE.md                 完整实测归档（结论/路径/流程/踩坑）
├── HANDOFF.md                 交接文档
└── pyproject.toml             可 pip install -e .
```

## 8. 4.1.13+ 为什么不可用（实测证据）

| 现象 | 实测结果 |
|---|---|
| 内存中 `x'<hex>'` 明文密钥 | **0 命中**（16 进程 / 1.6 GB） |
| 任意偏移的 32 字节原始密钥 | **0 命中**（stride-8 全量 2.26 亿候选 + salt 邻域 stride-1） |
| 本地文件中的密钥 | **0 命中**（含 `key_info.db` 284 条封装记录、MMKV、全部配置文件） |
| Windows CNG（bcrypt） | 运行期 **0 次调用**（`GenerateSymmetricKey`/`Decrypt`/`Encrypt`）→ 自带 AES |
| 反调试 | `DebugActiveProcess` + 硬件断点 **三次导致微信崩溃** |

结论：该版本密钥只在启动瞬间存在于代码内部，且进程有反调试保护 → 本机不可行。

## 9. 安全与合规

- 本工具用于**导出自己账号的聊天记录**。请勿用于未经授权的他人数据。
- `keys/`、`out/`、`decrypted/`、`snapshot/` 含**完整聊天内容与设备绑定密钥**，
  已在 `.gitignore` 中排除；如确需提交请用 `git add -f` 并自行承担风险。
- 备份 `out\all_keys.json`：只要库的 salt 不变，密钥长期有效（已验证跨版本升级）。

## 10. 脚本组织

`scripts/` 根目录只保留**可用链路**（15 个），调查过程脚本归档到 `scripts/_archive/`（60 个）。

### 10.1 根目录（可用链路）

| 脚本 | 用途 |
|---|---|
| `114_full_pipeline.py` | 全流程驱动：扫内存取密钥 + 解密全部库（含 WAL 回填） |
| `120_export_chats.py` | 导出聊天记录（JSON / Markdown / INDEX） |
| `200_analyze_style.py` | 表达方式定量分析 |
| `202_style_report.py` | 生成表达方式分析 Markdown 报告 |
| `73_kill_wechat.py` | 结束微信进程（沙箱下 `taskkill` 被拒，改用 `TerminateProcess`） |
| `92_where.py` | 定位微信主进程与 `Weixin.dll` 基址 |
| `01_extract_keys.py` / `10_extract_keys_admin.ps1` | 早期密钥提取（保留作对照） |
| `01_decrypt.ps1` / `02_wal_patch.py` / `03_probe_schema.py` | 早期解密与结构探测 |
| `30–33_get_*.cjs` | 依赖获取（frida / wechat-cli / wechat-extract 源码） |

> **日常使用只需 `wxarchive` 包，无需这些脚本**（`python -m wxarchive all`）。

### 10.2 归档（`scripts/_archive/`，60 个）

按主题记录调查全程与**关键负面结论**：Frida 注入实验、启动期截获（门控/挂起/硬件断点）、
AES-NI 与 codec 函数定位、参数标定与逐项排除（KDF/页大小/布局/密文区间/IV）。

**索引与结论见 `scripts/_archive/README.md`。**

> ⚠️ 归档脚本多数需要特定前置条件，`70–89` 区间的调试器/硬件断点方案**实测会导致微信崩溃**，请勿在正常使用时执行。

### 10.3 最终可用链路

```
wxarchive/  ←  推荐入口（自包含）
    └── 解密实现源自 tool/wechat-decrypt-main/decrypt_db.py（外部参考，已验证正确）
```

## 11. 已知限制

| 项 | 说明 |
|---|---|
| 4.1.13+ | 不支持 |
| 图片 `.dat` | 微信 4.x 用独立 AES 密钥，**未实现** |
| 语音/视频/文件 | 仅导出元数据与占位（`[语音]`/`[图片]`），未搬运媒体文件 |
| 未打开的库 | 某库若未被微信打开，其密钥不在内存 → 无密钥。打开对应界面（朋友圈/收藏/群聊）后重跑即可 |
| 平台 | 仅 Windows |
