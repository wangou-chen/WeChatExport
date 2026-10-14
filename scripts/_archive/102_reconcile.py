"""逐步对账：page-1 HMAC 校验的每一步中间值都打印出来。"""
import hashlib
import hmac
import struct
import sys

KEY = bytes.fromhex("ac52e88c6dc8e2b5913efeb6c9fc6f81cdb9a692039257e8396f6d7479640388")
DB = r"E:\xwechat_files\wxid_usdvuhs727dr22_2291\db_storage\message\message_0.db"
PAGESZ, SALT, MAC_OFF = 4096, 16, 4032


def main():
    with open(DB, "rb") as f:
        p1 = f.read(PAGESZ)
    print("db size =", __import__("os").path.getsize(DB))
    salt = p1[:SALT]
    print("salt            =", salt.hex())
    mac_salt = bytes(b ^ 0x3A for b in salt)
    print("mac_salt        =", mac_salt.hex())
    mac_key = hashlib.pbkdf2_hmac("sha512", KEY, mac_salt, 2, 32)
    print("mac_key         =", mac_key.hex())
    # 写法 A：与 90_verify_key.py 完全一致的切片
    ct_a = p1[SALT:PAGESZ - 80 + 16]
    ct_b = p1[16:4032]
    print("ct(A) len=%d  ct(B) len=%d  相同=%s" % (len(ct_a), len(ct_b), ct_a == ct_b))
    tag_a = p1[MAC_OFF:PAGESZ]
    tag_b = p1[4032:4096]
    print("tag(A) len=%d  tag(B) len=%d  相同=%s" % (len(tag_a), len(tag_b), tag_a == tag_b))
    for name, ct, tag in (("A", ct_a, tag_a), ("B", ct_b, tag_b)):
        h = hmac.new(mac_key, ct, hashlib.sha512)
        h.update(struct.pack("<I", 1))
        d = h.digest()
        print("  写法%s: computed=%s" % (name, d.hex()[:32]))
        print("         stored  =%s  match=%s" % (tag.hex()[:32], d == tag))
    print("\nMAC_OFF =", MAC_OFF, "-> p1[4032:4096] len =", len(p1[4032:4096]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
