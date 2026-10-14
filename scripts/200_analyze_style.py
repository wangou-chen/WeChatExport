"""分析单个联系人（翔铭）的表达方式：词汇、句式、标点、emoji、话题、互动节奏。

用法：
  set PYTHONUTF8=1
  C:\\Python314\\python.exe 200_analyze_style.py --chat 翔铭 --me 🎐
"""
import argparse
import collections
import datetime
import glob
import json
import os
import re
import sys

BASE = r"C:\Users\Lenovo\Desktop\WeChatExport"

# 常见语气词/口头禅候选（中文）
PARTICLES = ["啊", "呀", "吧", "呢", "吗", "嘛", "哦", "噢", "喔", "诶", "唉", "哎", "哈",
             "嘿", "嘞", "啦", "咯", "喽", "嗯", "唔", "呃", "额", "emmm", "emm", "em",
             "哈哈", "哈哈哈", "呵呵", "嘻嘻", "嘿嘿", "草", "靠", "淦", "卧槽", "我靠"]
# 表情类字符（emoji 粗筛）
EMOJI_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F000-\U0001F2FF"
    "\U00002190-\U000021FF\U00002B00-\U00002BFF\uFE0F\u200D]+")
PUNCT = "，。！？、；：～~…—,.!?;:'\""


def load(chat: str):
    fs = glob.glob(os.path.join(BASE, "out", "single", "chat_%s*.json" % chat))
    if not fs:
        raise SystemExit("未找到导出文件：out\\single\\chat_%s*.json（先运行 wxarchive chat）" % chat)
    j = json.load(open(fs[0], encoding="utf-8"))
    return j["sessions"][0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chat", default="翔铭")
    ap.add_argument("--me", default="🎐")
    ap.add_argument("--out", default=os.path.join(BASE, "out", "analysis"))
    args = ap.parse_args()

    s = load(args.chat)
    ms = s["messages"]
    name = s["display"]
    him = [m for m in ms if m["sender"] == name]
    mine = [m for m in ms if m["sender"] == args.me]
    texts = [m["text"].strip() for m in him
             if m["type_name"] == "文本" and m["text"] and m["text"].strip()]

    os.makedirs(args.out, exist_ok=True)
    rep = {}
    rep["meta"] = {
        "会话": name, "username": s["username"], "消息表": s["table"],
        "总消息": len(ms), "他": len(him), "我": len(mine),
        "时间跨度": "%s ~ %s" % (
            datetime.datetime.fromtimestamp(ms[0]["time"]).strftime("%Y-%m-%d"),
            datetime.datetime.fromtimestamp(ms[-1]["time"]).strftime("%Y-%m-%d")),
        "文本条数": len(texts),
    }

    # 长度
    lens = [len(t) for t in texts]
    rep["length"] = {
        "平均": round(sum(lens) / max(1, len(lens)), 2),
        "中位": sorted(lens)[len(lens) // 2] if lens else 0,
        "P90": sorted(lens)[int(len(lens) * 0.9)] if lens else 0,
        "最长": max(lens) if lens else 0,
        "≤2字": sum(1 for l in lens if l <= 2),
        "≤8字": sum(1 for l in lens if l <= 8),
        ">50字": sum(1 for l in lens if l > 50),
    }

    # 语气词/口头禅
    cnt = collections.Counter()
    for t in texts:
        for p in PARTICLES:
            if p in t.lower():
                cnt[p] += 1
    rep["particles"] = cnt.most_common(20)

    # 句尾字符
    tail = collections.Counter(t[-1] for t in texts if t)
    rep["tail_chars"] = tail.most_common(15)

    # 标点使用率
    with_punct = sum(1 for t in texts if any(c in t for c in PUNCT))
    rep["punct"] = {
        "含标点的条数": with_punct,
        "占比": round(with_punct / max(1, len(texts)), 3),
        "句末问号": sum(1 for t in texts if t.rstrip().endswith(("?", "？"))),
        "句末叹号": sum(1 for t in texts if t.rstrip().endswith(("!", "！"))),
        "句末句号": sum(1 for t in texts if t.rstrip().endswith(("。", "."))),
        "省略号": sum(1 for t in texts if "..." in t or "…" in t),
    }

    # emoji
    emo = collections.Counter()
    emo_msgs = 0
    for t in texts:
        found = EMOJI_RE.findall(t)
        if found:
            emo_msgs += 1
            for e in found:
                emo[e] += 1
    rep["emoji"] = {"含emoji条数": emo_msgs,
                    "占比": round(emo_msgs / max(1, len(texts)), 3),
                    "top": emo.most_common(20)}

    # 高频短句（整条消息重复≥3次）
    whole = collections.Counter(t for t in texts if len(t) <= 12)
    rep["habit_phrases"] = [(t, c) for t, c in whole.most_common(40) if c >= 3]

    # 高频 2-4 字片段
    frag = collections.Counter()
    for t in texts:
        for n in (2, 3, 4):
            for i in range(len(t) - n + 1):
                if all('\u4e00' <= ch <= '\u9fff' or ch.isalnum() for ch in t[i:i + n]):
                    frag[t[i:i + n]] += 1
    rep["fragments"] = [(f, c) for f, c in frag.most_common(60) if c >= 5]

    # 互动节奏：连发（同一人连续消息数）
    seq = []
    cur = None
    n = 0
    for m in ms:
        if m["sender"] == cur:
            n += 1
        else:
            if cur is not None:
                seq.append((cur, n))
            cur = m["sender"]
            n = 1
    seq.append((cur, n))
    his_bursts = [n for who, n in seq if who == name]
    rep["rhythm"] = {
        "他发的连发段数": len(his_bursts),
        "平均连发条数": round(sum(his_bursts) / max(1, len(his_bursts)), 2),
        "最长连发": max(his_bursts) if his_bursts else 0,
        "连发≥3次的比例": round(sum(1 for x in his_bursts if x >= 3) / max(1, len(his_bursts)), 3),
    }

    # 时段分布
    hours = collections.Counter(
        datetime.datetime.fromtimestamp(m["time"]).hour for m in him)
    rep["hours"] = sorted(hours.items())

    # 月分布
    months = collections.Counter(
        datetime.datetime.fromtimestamp(m["time"]).strftime("%Y-%m") for m in him)
    rep["months"] = sorted(months.items())

    # 他是否是问句/回应方
    ask = sum(1 for t in texts if t.rstrip().endswith(("?", "？")) or "吗" in t[-3:])
    rep["asking"] = {"问句数": ask, "占比": round(ask / max(1, len(texts)), 3)}

    # 非文本消息（表情包/图片/语音）
    others = collections.Counter(m["type_name"] for m in him if m["type_name"] != "文本")
    rep["non_text"] = others.most_common()

    # 输出 JSON 供后续引用
    jp = os.path.join(args.out, "_style_stats.json")
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)

    # 打印人类可读摘要
    print("会话:", rep["meta"]["会话"], "|", rep["meta"]["时间跨度"])
    print("消息: 总%d 他%d 我%d | 文本%d条" % (rep["meta"]["总消息"], rep["meta"]["他"],
                                            rep["meta"]["我"], rep["meta"]["文本条数"]))
    print("长度: 平均%.1f 中位%d P90=%d 最长%d | ≤8字占%.0f%%" % (
        rep["length"]["平均"], rep["length"]["中位"], rep["length"]["P90"],
        rep["length"]["最长"],
        100 * rep["length"]["≤8字"] / max(1, len(texts))))
    print("标点: 含标点%.0f%% 问号%d 叹号%d 句号%d 省略号%d" % (
        rep["punct"]["占比"] * 100, rep["punct"]["句末问号"], rep["punct"]["句末叹号"],
        rep["punct"]["句末句号"], rep["punct"]["省略号"]))
    print("emoji: %d条(%.0f%%) top=%s" % (
        rep["emoji"]["含emoji条数"], rep["emoji"]["占比"] * 100,
        [e for e, _ in rep["emoji"]["top"][:8]]))
    print("语气词 top:", rep["particles"][:12])
    print("句尾字符 top:", rep["tail_chars"][:12])
    print("习惯短句(≥3次):", rep["habit_phrases"][:20])
    print("高频片段(≥5次):", rep["fragments"][:25])
    print("连发: 段数%d 平均%.1f 最长%d ≥3比例%.0f%%" % (
        rep["rhythm"]["他发的连发段数"], rep["rhythm"]["平均连发条数"],
        rep["rhythm"]["最长连发"], rep["rhythm"]["连发≥3次的比例"] * 100))
    print("非文本消息:", rep["non_text"])
    print("问句占比: %.0f%%" % (rep["asking"]["占比"] * 100))
    print("-> %s" % jp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
