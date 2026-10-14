"""wxarchive —— 微信 4.0.x 本地聊天记录导出库（自足实现，无外部工具依赖）

在本机（Windows / 微信 4.0.3.39）实测通过：
    677 会话 / 7,303 联系人 / 460,691 条消息 → JSON + Markdown

核心结论（本库据此实现）：
  1. 密钥：进程内存中的 ASCII 文本 x'<64hex enc_key><32hex salt>'（98 字符）
  2. 用法：enc_key 的 32 字节**原值直接作 AES-256 密钥**（raw-key 模式，不做 KDF 派生）
  3. 每库一钥：salt 各不相同，需按 salt 逐库配对
  4. 页布局：page_size=4096, reserved=80
        page1 = [0:16] 明文 salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] tag
        pageN = [0:4016] 密文       | [4016:4032] IV | [4032:4096] tag
  5. WAL：帧 = 24B 头 + 4096B 页，用同一 enc_key 解后按 pgno 回填
"""

__version__ = "1.0.0"
__all__ = ["crypto", "keys", "decrypt", "export", "sessions", "cli"]
