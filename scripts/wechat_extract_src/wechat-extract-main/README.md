# 微信 4.x 数据提取

> 运行环境：Windows | 适用：微信 4.0+（进程名 Weixin.exe）| 提前在电脑上导入聊天记录 | 只读操作，不修改微信文件

---

## 给人看的

微信 4.x 用 WCDB（基于 SQLCipher）加密所有本地数据库。好消息是，微信运行时会把加密密钥以明文形式留在进程内存里，格式为 `x'<64位密钥><32位salt>'` 的 ASCII 字符串，共 98 个字符。

整个流程分六步：

1. **找到微信进程和数据目录** — 微信数据库在 `Documents\xwechat_files\<你的wxid>\db_storage\` 下
2. **从 DB 文件提取 salt** — 每个加密 DB 的第 1 页前 16 字节就是 salt
3. **从内存扫描密钥** — 用 Windows API 遍历微信进程内存，搜索 `x'<96位hex>'`，salt 匹配即确认对应 DB
4. **用 pysqlcipher3 解密** — 拼接 key+salt 打开数据库，导出为普通 SQLite
5. **提取消息** — 处理 WCDB zstd 压缩，映射发送者到通讯录昵称

### 关于图片

微信 4.x 的图片 `.dat` 文件使用 AES 加密（不是旧版 XOR），目前没有可用公开工具解密。

---

## 给Agent看的

### 前置准备

```powershell
# 1. Python >= 3.8
python --version

# 2. 安装依赖（zstd 非 zstandard！）
pip install zstd pysqlcipher3

# 3. pysqlcipher3 若安装失败（Windows 常见），使用预编译 wheel：
#    pip install pysqlcipher3 --only-binary :all:
#    或从 https://github.com/coleifer/pysqlcipher3 编译
```

### 步骤 1：定位微信进程和数据目录

```python
import subprocess, os, glob

# 获取 Weixin.exe PID
out = subprocess.check_output('tasklist /FI "IMAGENAME eq Weixin.exe" /FO CSV', shell=True).decode('gbk')
lines = [l.strip('"').split('","') for l in out.strip().split('\n')[1:] if l.strip()]
pids = [int(l[1]) for l in lines if len(l) >= 2 and l[1].isdigit()]
if not pids:
    raise RuntimeError("未找到 Weixin.exe 进程，请确保微信已启动")
PID = pids[0]
print(f"微信 PID: {PID}")

# 定位数据目录
candidates = glob.glob(os.path.expandvars(r"%USERPROFILE%\Documents\xwechat_files\*\db_storage"))
db_dir = candidates[0] if candidates else None
print(f"数据目录: {db_dir}")
```

**Agent 注意**：如果 `Documents\xwechat_files` 不存在，检查 `%APPDATA%\Tencent\xwechat\`。

### 步骤 2：从 DB 文件提取 salt

```python
salts = {}  # db_name -> salt_hex
for root, dirs, files in os.walk(db_dir):
    for f in files:
        if f.endswith(".db"):
            path = os.path.join(root, f)
            with open(path, "rb") as fh:
                page1 = fh.read(4096)
            salts[f] = page1[:16].hex()
```

### 步骤 3：扫描微信进程内存提取密钥

核心原理：遍历微信进程所有可读内存区域，正则搜索 `x'<96位hex>'` ASCII 字符串，用步骤 2 的 salt 做匹配。

```python
import ctypes, ctypes.wintypes as wt, re

kernel32 = ctypes.windll.kernel32
h = kernel32.OpenProcess(0x0010 | 0x0400, False, PID)  # PROCESS_VM_READ|PROCESS_QUERY_INFORMATION

class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]

# 枚举 MEM_COMMIT 且非 PAGE_NOACCESS 的区域
regions = []
addr = 0
mbi = MBI()
while addr < 0x7FFFFFFFFFFF:
    if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
        break
    if mbi.State == 0x1000 and mbi.Protect != 0x01:
        if 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regions.append((mbi.BaseAddress, mbi.RegionSize))
    nxt = mbi.BaseAddress + mbi.RegionSize
    if nxt <= addr:
        break
    addr = nxt

# 逐 1MB 块搜索 x'<96hex>' 模式
hex_pattern = re.compile(rb"x'([0-9a-fA-F]{96})'")
salt_set = set(salts.values())
keys = {}
salt_to_db = {v: k for k, v in salts.items()}

for base, size in regions:
    offset = 0
    while offset < size:
        chunk_sz = min(1024 * 1024, size - offset)
        buf = ctypes.create_string_buffer(chunk_sz)
        nread = ctypes.c_size_t(0)
        if kernel32.ReadProcessMemory(h, ctypes.c_uint64(base + offset), buf, chunk_sz, ctypes.byref(nread)):
            for m in hex_pattern.finditer(buf.raw[:nread.value]):
                hex_str = m.group(1).decode()
                enc_key = hex_str[:64]
                salt = hex_str[64:]
                if salt in salt_to_db:
                    keys[salt_to_db[salt]] = {"enc_key": enc_key, "salt": salt}
        offset += chunk_sz

kernel32.CloseHandle(h)

# 保存
import json
with open("wechat_keys.json", "w") as f:
    json.dump(keys, f, indent=2)
```

**踩坑记录**：
- 微信 4.1+ 不缓存原始密钥，只缓存 raw key（enc_key+salt 拼接）
- 扫描不到 key 时，尝试扫描子进程 WeChatAppEx.exe 的内存
- 所有 hex 均为小写

### 步骤 4：用 pysqlcipher3 解密

```python
from pysqlcipher3 import dbapi2 as sqlcipher

hex_key = enc_key + salt  # 64+32 hex = 96 位

conn = sqlcipher.connect("<db文件路径>")
c = conn.cursor()
c.execute(f"PRAGMA key = \"x'{hex_key}'\"")
c.execute("PRAGMA cipher_page_size = 4096")
c.execute("PRAGMA kdf_iter = 64000")
c.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
c.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1")
c.execute("PRAGMA cipher_migrate")

# 验证
c.execute("SELECT COUNT(*) FROM sqlite_master")
if c.fetchone()[0] == 0:
    raise Exception("解密失败：无表（key 错误或 cipher 参数不匹配）")

# 导出为普通 SQLite
conn.execute("ATTACH DATABASE 'decrypted.db' AS plain KEY ''")
conn.execute("SELECT sqlcipher_export('plain')")
conn.execute("DETACH plain")
conn.close()
```

**踩坑记录**：cipher_migrate 用于兼容不同 SQLCipher 版本，解密后 DB 仍保留 WCDB 压缩字段。

### 步骤 5：提取消息

**前置**：`pip install zstd`（注意是 `zstd` 不是 `zstandard`）。

**群聊表定位**：`Msg_` + 群 ID 的 MD5（取前 32 位）。群 ID 可从 `session.db` 的 SessionTable 按群名查找。

**WCDB 解压**：

```python
import zstd, sqlite3

def decompress(data, ct):
    if ct == 0:  # 明文
        return data.decode('utf-8', errors='replace') if isinstance(data, bytes) else data
    elif ct == 4:  # zstd 压缩
        return zstd.decompress(data).decode('utf-8', errors='replace')
    else:
        return data  # 未知，保留原始
```

**文本提取**：`message_content` 优先于 `source`（source 是 XML 元数据含签名垃圾）：

```python
msg_text = decompress(row['message_content'], row['WCDB_CT_message_content'])
if not msg_text:
    msg_text = decompress(row['source'], row['WCDB_CT_source'])
# 去 wxid 前缀
import re
msg_text = re.sub(r'^wxid_[a-z0-9]+:\s*\n?', '', msg_text)
```

**发送者映射链**（关键！需跨两个 DB）：

```
real_sender_id → 消息DB.Name2Id.rowid → user_name(wxid) → 联系人DB.contact → coalesce(remark, nick_name, username)
```

```python
# 消息 DB 内的 Name2Id 表（列名 user_name，非 username！）
msg_conn = sqlite3.connect("decrypted_msg.db")
name2id = dict(msg_conn.execute("SELECT rowid, user_name FROM Name2Id"))

# 联系人 DB
contact_conn = sqlite3.connect("decrypted_contact.db")
contact_info = {}
for row in contact_conn.execute("SELECT username, remark, nick_name FROM contact"):
    contact_info[row[0]] = row[1] or row[2] or row[0]

def get_sender_name(real_sender_id):
    wxid = name2id.get(real_sender_id)
    if wxid:
        return contact_info.get(wxid, wxid)
    return str(real_sender_id)
```

**踩坑记录**：
- Name2Id 在消息 DB 内，不在 contact.db。列名 `user_name` 非 `username`
- text 类优先用 `message_content`；appmsg 类从 source 的 XML `<title>` 提取

### 步骤 6：解析特殊消息类型

先查 `local_type` 按类型处理（完整表见 [附录A](#附录a消息类型参考)）。

**appmsg 类**：source 解压后是 XML，从 `<title>` 提取：

```python
import re

def extract_title(xml_text):
    m = re.search(r'<title><!\[CDATA\[(.*?)\]\]></title>', xml_text, re.DOTALL)
    if m: return m.group(1)
    m = re.search(r'<title>(.*?)</title>', xml_text, re.DOTALL)
    if m: return m.group(1)
    return xml_text  # 降级
```

**群接龙**（`local_type=227633266737`）：

```python
import html

m = re.search(r'<solitaire_info><!\[CDATA\[(.*?)\]\]></solitaire_info>', xml_text, re.DOTALL)
if m:
    unescaped = html.unescape(m.group(1))
    participants = re.findall(r'<u>([^<]+)</u>', unescaped)
```

**踩坑记录**：
- title 不一定有 CDATA，两种格式都要处理
- solitaire_info 内容是 HTML-escaped，需 `html.unescape()`

### 步骤 7：应对 DB 过期

解密 DB 是某个时刻的快照。微信持续运行后加密 DB 会膨胀（5 倍以上），需重新解密：

```python
# 方案：直接用 sqlcipher 重新 ATTACH 导出
# key 不变则 HMAC 仍然通过
from pysqlcipher3 import dbapi2 as sqlcipher

conn = sqlcipher.connect("<最新加密DB路径>")
c = conn.cursor()
c.execute(f"PRAGMA key = \"x'{hex_key}'\"")
# ... 同步骤 4 的 PRAGMA 序列 ...
conn.execute("ATTACH DATABASE 'redecrypted.db' AS plain KEY ''")
conn.execute("SELECT sqlcipher_export('plain')")
conn.execute("DETACH plain")
conn.close()
```

或者 git clone `wcdb-key-tool`（GitHub: TANGandXUE/wcdb-key-tool）并调用其 `_decrypt_database` 函数。

---

## 附录A：消息类型参考

| local_type | 含义 | 备注 |
|-----------|------|------|
| 1 | 文本 | `message_content` 优先 |
| 3 | 图片 | `.dat` AES 加密，无法解密 |
| 34 | 语音 | 音频文件在 `msg/attach/` |
| 47 | 表情 | 静态/动态表情 |
| 10000/10002 | 系统消息 | 群名变更、成员进出等 |
| 373662154801 | @所有人公告 | appmsg，从 `<title>` 提取 |
| 227633266737 | 群接龙 | appmsg，需 html.unescape |
| 244813135921 | 视频号分享 | appmsg，从 `<title>` 提取 |            

---

## 附录B：图片 .dat 文件

图片存储在 `msg/attach/<群ID MD5>/Img/` 下，文件名不带后缀。

- 微信 4.x 用 **AES 加密**，不是旧版 XOR
- **目前没有可用的公开工具解密**

---

## 参考

- [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) — PBKDF2 派生 + 多平台
- [328336690/wechat-decrypt](https://github.com/328336690/wechat-decrypt) — 微信 4.0 专用内存提取
- [Laster-dev/WeChat-Dump-Auto](https://github.com/Laster-dev/WeChat-Dump-Auto) — C/C#/C++ 三版本
