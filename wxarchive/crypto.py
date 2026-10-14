"""SQLCipher 4 页面加解密（微信 4.0.x 实测参数）

关键点（踩坑记录）：
  * 密钥来源：内存中的 32 字节 enc_key **直接使用**，不要做 PBKDF2 派生。
    误加派生会导致 12000+ 组参数全失败，且 page1 仍会"恰好"解出 SQLite 头前 16 字节，极难定位。
  * 密文区间：page1 = [16 : 4016)（4000 B），pageN = [0 : 4016)。
    IV 位于 [4016 : 4032)。写成 [16:4032) 会多取一整块导致全错。
"""
import hashlib
import hmac as hmac_mod
import os
import struct

from ._bootstrap import ensure_dep

ensure_dep("Crypto", "pycryptodome")

from Crypto.Cipher import AES                                   # noqa: E402

PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
RESERVED = 80                      # IV(16) + HMAC(64)
CT_END = PAGE_SIZE - RESERVED      # 4016
MAC_OFF = PAGE_SIZE - HMAC_SIZE    # 4032
SQLITE_HDR = b"SQLite format 3\x00"

WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24
BTREE_TYPES = (0x0D, 0x05, 0x0A, 0x02)


class DecryptError(Exception):
    pass


# --------------------------------------------------------------------- 密钥校验

def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    """HMAC 侧派生：PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3A, 2, 32)"""
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, 32)


def page_tag(mac_key: bytes, ciphertext: bytes, pgno: int) -> bytes:
    h = hmac_mod.new(mac_key, ciphertext, hashlib.sha512)
    h.update(struct.pack("<I", pgno))
    return h.digest()


def verify_page1(enc_key: bytes, page1: bytes) -> bool:
    """HMAC 校验 page1（仅作辅助判据；内存中同 salt 可能残留历史密钥，HMAC 会误否）。"""
    salt = page1[:SALT_SIZE]
    ct = page1[SALT_SIZE:CT_END]
    tag = page1[MAC_OFF:PAGE_SIZE]
    return page_tag(derive_mac_key(enc_key, salt), ct, 1) == tag


# --------------------------------------------------------------------- 页面解密

def decrypt_page(enc_key: bytes, page: bytes, pgno: int) -> bytes:
    """解密单页，输出 4096 字节标准 SQLite 页。"""
    if len(page) < PAGE_SIZE:
        page = page + b"\x00" * (PAGE_SIZE - len(page))
    iv = page[CT_END:CT_END + IV_SIZE]
    if pgno == 1:
        body = page[SALT_SIZE:CT_END]
        dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(body)
        return SQLITE_HDR + dec + b"\x00" * RESERVED
    body = page[0:CT_END]
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(body)
    return dec + b"\x00" * RESERVED


def check_key(enc_key: bytes, page1: bytes, page2: bytes = None) -> bool:
    """判定密钥是否正确：page1 解出 SQLite 头 + page_size=4096；page2 首字节为 b-tree 类型。

    这是比 HMAC 更可靠的判据（内存里同一 salt 会残留多把历史密钥）。
    """
    try:
        d1 = decrypt_page(enc_key, page1, 1)
    except Exception:                                             # noqa: BLE001
        return False
    if d1[:16] != SQLITE_HDR or int.from_bytes(d1[16:18], "big") != PAGE_SIZE:
        return False
    if page2:
        try:
            d2 = decrypt_page(enc_key, page2, 2)
        except Exception:                                         # noqa: BLE001
            return False
        if d2[0] not in BTREE_TYPES:
            return False
    return True


# --------------------------------------------------------------------- 整库解密

def decrypt_db(src: str, dst: str, enc_key: bytes, progress=None) -> int:
    """解密整个数据库文件，返回页数。"""
    size = os.path.getsize(src)
    npages = size // PAGE_SIZE
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for pgno in range(1, npages + 1):
            page = fin.read(PAGE_SIZE)
            if len(page) < PAGE_SIZE:
                break
            fout.write(decrypt_page(enc_key, page, pgno))
            if progress and pgno % 10000 == 0:
                progress(pgno, npages)
    return npages


def decrypt_wal(wal_path: str, decrypted_db: str, enc_key: bytes) -> int:
    """解密 WAL 帧并按 pgno 回填到已解密的库，返回回填帧数。"""
    if not os.path.exists(wal_path):
        return 0
    size = os.path.getsize(wal_path)
    if size <= WAL_HEADER_SIZE:
        return 0
    patched = 0
    with open(wal_path, "rb") as wf, open(decrypted_db, "r+b") as df:
        hdr = wf.read(WAL_HEADER_SIZE)
        ws1 = struct.unpack(">I", hdr[16:20])[0]
        ws2 = struct.unpack(">I", hdr[20:24])[0]
        frame = WAL_FRAME_HEADER_SIZE + PAGE_SIZE
        while wf.tell() + frame <= size:
            fh = wf.read(WAL_FRAME_HEADER_SIZE)
            if len(fh) < WAL_FRAME_HEADER_SIZE:
                break
            pgno = struct.unpack(">I", fh[0:4])[0]
            s1 = struct.unpack(">I", fh[8:12])[0]
            s2 = struct.unpack(">I", fh[12:16])[0]
            ep = wf.read(PAGE_SIZE)
            if len(ep) < PAGE_SIZE:
                break
            if pgno == 0 or pgno > 10_000_000:
                continue
            if s1 != ws1 or s2 != ws2:
                continue
            df.seek((pgno - 1) * PAGE_SIZE)
            df.write(decrypt_page(enc_key, ep, pgno))
            patched += 1
    return patched
