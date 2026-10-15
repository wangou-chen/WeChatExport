"""生成某位联系人的「表达方式与对话模式」分析 Markdown。

通用化：通过 --chat 选择已导出的会话，--who 指定被分析者，--pronoun 指定代词。

用法：
  set PYTHONUTF8=1
  python 202_style_report.py --chat 小狗媳妇 --who "小狗媳妇 ᝰꫛꫀꪝ" --pronoun 她 --label 小狗媳妇
  python 202_style_report.py --chat 翔铭 --pronoun 他
"""
import argparse
import collections
import datetime
import glob
import json
import os
import re
import sys

BASE = os.environ.get('WXARCHIVE_BASE') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F000-\U0001F2FF\uFE0F]")
TAG_RE = re.compile(r"^\[[^\[\]]{1,12}\]$")
PUNCT = "，。！？、；：～~…—,.!?;:\"'"

# 引用/转发的他人文本特征（不属本人语体）
QUOTE_HINTS = ("AI的关键观察", "AI指出", "AI总结", "完整解读", "你们两人",
               "活动通知", "活动时间", "活动地点", "活动内容",
               "合盘", "星盘", "上升天蝎", "太阳巨蟹")

FILLERS = {
    "啊": "软化语气/感叹", "呀": "轻度感叹", "吧": "弱化断言/建议", "哦": "应答、恍然",
    "嗯": "确认、同意", "哎": "起句、叹气", "哈": "笑声（哈哈）", "嘿": "笑声（嘿嘿）",
    "哼": "撒娇/不满", "嘛": "语气缓冲", "呢": "持续/反问", "吗": "疑问",
}
HEDGES = ["我觉得", "我感觉", "我估计", "我猜", "可能", "应该", "大概", "其实",
          "说实话", "确实", "反正", "感觉", "觉得", "有点", "好像", "应该是"]
AGREE = ["对", "对呀", "太对了", "确实", "可以", "okk", "ok", "行", "好的", "嗯嗯",
         "嗯呢", "好", "是", "对的对的", "没问题"]
SLANG = ["我靠", "靠", "草", "淦", "绷", "绝了", "寄", "麻了", "小丑", "笑死", "666",
         "牛逼", "服了", "真服了", "无语"]


def load(chat):
    # 首选 <out>\single\（wxarchive chat 的标准产物位置）；回退兼容旧版写在 out\ 根目录的文件。
    pats = [os.path.join(BASE, "out", "single", "chat_%s*.json" % chat),
            os.path.join(BASE, "out", "chat_%s*.json" % chat)]
    fs = []
    for p in pats:
        fs = glob.glob(p)
        if fs:
            break
    if not fs:
        raise SystemExit("未找到 out\\single\\chat_%s*.json（先运行 wxarchive chat）" % chat)
    return json.load(open(fs[0], encoding="utf-8"))["sessions"][0]


def burst_stats(ms, who):
    seq, cur, n = [], None, 0
    for m in ms:
        if m["sender"] == cur:
            n += 1
        else:
            if cur is not None:
                seq.append((cur, n))
            cur, n = m["sender"], 1
    seq.append((cur, n))
    return [x for w, x in seq if w == who]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chat", required=True)
    ap.add_argument("--who", default="")
    ap.add_argument("--me", default="🎐")
    ap.add_argument("--pronoun", default="他")
    ap.add_argument("--label", default="")
    ap.add_argument("--out", default=os.path.join(BASE, "out", "analysis"))
    args = ap.parse_args()

    s = load(args.chat)
    ms = s["messages"]
    TA = args.pronoun
    name = args.who or s["display"]
    senders = sorted({m["sender"] for m in ms if m["sender"]})
    if name not in senders:
        raise SystemExit("会话中没有发送者 %r。实际发送者：%s" % (name, senders))

    him = [m for m in ms if m["sender"] == name]
    alltxt = [m["text"].strip() for m in him
              if m["type_name"] == "文本" and m["text"] and m["text"].strip()]
    quoted = [t for t in alltxt if any(q in t for q in QUOTE_HINTS)]
    texts = [t for t in alltxt if not any(q in t for q in QUOTE_HINTS)]
    lens = [len(t) for t in texts]
    n_txt = max(1, len(texts))
    tags = collections.Counter(t.strip() for t in texts if TAG_RE.match(t.strip()))
    tag_msgs = sum(tags.values())
    b = burst_stats(ms, name)
    hours = collections.Counter(datetime.datetime.fromtimestamp(m["time"]).hour for m in him)
    months = collections.Counter(
        datetime.datetime.fromtimestamp(m["time"]).strftime("%Y-%m") for m in him)
    whole = collections.Counter(t for t in texts if len(t) <= 12)
    frag = collections.Counter()
    for t in texts:
        for n in (2, 3):
            for i in range(len(t) - n + 1):
                seg = t[i:i + n]
                if all("\u4e00" <= ch <= "\u9fff" or ch.isalnum() for ch in seg):
                    frag[seg] += 1

    long_own = sorted([t for t in texts if len(t) > 35], key=len, reverse=True)
    hedge_msgs = [t for t in texts if any(h in t for h in HEDGES)]
    ask_msgs = [t for t in texts if t.rstrip().endswith(("?", "？")) or t.endswith(("吗", "呢"))]
    slang_msgs = [t for t in texts if any(x in t for x in SLANG)]
    agree_msgs = [t for t in texts if t in AGREE or any(t.startswith(a) for a in AGREE)]
    # 连发示例（同一人连续 ≥4 条）
    burst_ex = []
    cur, buf = None, []
    for m in ms:
        if m["sender"] == cur:
            buf.append(m["text"] if m["type_name"] == "文本" else "[%s]" % m["type_name"])
        else:
            if cur == name and len(buf) >= 4:
                burst_ex.append(buf[:6])
            cur, buf = m["sender"], [m["text"] if m["type_name"] == "文本" else "[%s]" % m["type_name"]]
    if cur == name and len(buf) >= 4:
        burst_ex.append(buf[:6])

    md = []
    A = md.append
    A("# %s · 表达方式与对话模式分析\n" % name)
    A("> 数据来源：微信私聊导出（`out\\single\\chat_%s.json`）  " % args.chat)
    A("> 样本量：**%s发的 %d 条**，其中纯文本 **%d 条**（已剔除 %d 条引用/转发文本）；对话总计 %d 条  "
      % (TA, len(him), len(texts), len(quoted), len(ms)))
    A("> 时间跨度：%s ~ %s  " % (
        datetime.datetime.fromtimestamp(ms[0]["time"]).strftime("%Y-%m-%d"),
        datetime.datetime.fromtimestamp(ms[-1]["time"]).strftime("%Y-%m-%d")))
    A("> 对方视角：`%s`  " % args.me)
    A("> 生成时间：%s\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    A("---\n")

    A("## 一、总体画像\n")
    A("| 维度 | 实测值 | 解读 |")
    A("|---|---|---|")
    A("| 消息总量 | %s %d / 对话 %d（占 %.0f%%） | 双方发言量对比 |"
      % (TA, len(him), len(ms), 100.0 * len(him) / max(1, len(ms))))
    A("| 纯文本条数 | %d（占其消息 %.0f%%） | 其余为语音/表情/图片等 |"
      % (len(texts), 100.0 * len(texts) / max(1, len(him))))
    A("| 语音消息 | **%d 条（%.0f%%）** | 语音依赖度 |"
      % (sum(1 for m in him if m["type_name"] == "语音"),
         100.0 * sum(1 for m in him if m["type_name"] == "语音") / max(1, len(him))))
    A("| 文本平均长度 | **%.1f 字**（中位 %d，P90 %d，最长 %d） | 句长特征 |"
      % (sum(lens) / n_txt, sorted(lens)[len(lens) // 2],
         sorted(lens)[int(len(lens) * 0.9)], max(lens)))
    A("| ≤8 字占比 | **%.0f%%** | 短句/单词级回应占比 |"
      % (100.0 * sum(1 for l in lens if l <= 8) / n_txt))
    A("| ≤2 字占比 | %.0f%% | 极短回应 |" % (100.0 * sum(1 for l in lens if l <= 2) / n_txt))
    A("| 含标点占比 | **仅 %.0f%%** | 打标点习惯 |"
      % (100.0 * sum(1 for t in texts if any(c in t for c in PUNCT)) / n_txt))
    A("| 句末问号 | %d 条（%.0f%%） | 追问频率 |"
      % (sum(1 for t in texts if t.rstrip().endswith(("?", "？"))),
         100.0 * sum(1 for t in texts if t.rstrip().endswith(("?", "？"))) / n_txt))
    A("| emoji 符号 | %d 条 | 是否用真 emoji |"
      % sum(1 for t in texts if EMOJI_RE.search(t)))
    A("| 微信表情标签 | %d 条 / %d 种 | %s |"
      % (tag_msgs, len(tags), " ".join("`%s`" % t for t, _ in tags.most_common(6))))
    A("| 连发（burst） | 平均 **%.1f 条**/段，最长 %d，≥3 条占 %.0f%% | 一条想法拆几条发 |"
      % (sum(b) / max(1, len(b)), max(b) if b else 0,
         100.0 * sum(1 for x in b if x >= 3) / max(1, len(b))))
    A("")

    A("## 二、语言风格特征\n")
    A("### 2.1 句长与结构\n")
    A("- 平均 **%.1f 字**、中位 **%d 字**；≤8 字占 **%.0f%%**，≤2 字占 **%.0f%%**。"
      % (sum(lens) / n_txt, sorted(lens)[len(lens) // 2],
         100.0 * sum(1 for l in lens if l <= 8) / n_txt,
         100.0 * sum(1 for l in lens if l <= 2) / n_txt))
    A("- 超过 35 字的「长消息」共 **%d 条**（%.1f%%）：" % (len(long_own),
                                                        100.0 * len(long_own) / n_txt))
    for t in long_own[:4]:
        A("  - > %s%s" % (t[:130].replace("\n", " "), "…" if len(t) > 130 else ""))
    A("")

    A("### 2.2 标点习惯\n")
    A("- 含标点仅 **%.0f%%**；句末问号 %d 条、叹号 %d 条、句号 %d 条、省略号 %d 条。"
      % (100.0 * sum(1 for t in texts if any(c in t for c in PUNCT)) / n_txt,
         sum(1 for t in texts if t.rstrip().endswith(("?", "？"))),
         sum(1 for t in texts if t.rstrip().endswith(("!", "！"))),
         sum(1 for t in texts if t.rstrip().endswith(("。", "."))),
         sum(1 for t in texts if "..." in t or "…" in t)))
    A("")

    A("### 2.3 语气词与口头禅（实测频次）\n")
    A("| 语气词 | 次数 | 作用 |")
    A("|---|---|---|")
    for p, desc in FILLERS.items():
        c = sum(1 for t in texts if p in t)
        if c:
            A("| `%s` | %d | %s |" % (p, c, desc))
    A("")

    A("### 2.4 高频整句（原样重复 ≥3 次）\n")
    for t, c in [(t, c) for t, c in whole.most_common(40) if c >= 3][:22]:
        A("- `%s` × %d" % (t, c))
    A("")

    A("### 2.5 表情与语音：非文本表达占 %.0f%%\n"
      % (100.0 * sum(1 for m in him if m["type_name"] != "文本") / max(1, len(him))))
    A("- 非文本构成：%s" % "、".join(
        "%s %d" % (k, v) for k, v in
        collections.Counter(m["type_name"] for m in him
                            if m["type_name"] != "文本").most_common(8)))
    A("- 常用表情标签：%s"
      % "、".join("`%s`×%d" % (t, c) for t, c in tags.most_common(8)))
    A("")

    A("## 三、对话模式（互动层）\n")
    A("### 3.1 连发节奏\n")
    A("- 平均一次连发 **%.1f 条**，最长 **%d 条**；≥3 条的连发占 **%.0f%%**。"
      % (sum(b) / max(1, len(b)), max(b) if b else 0,
         100.0 * sum(1 for x in b if x >= 3) / max(1, len(b))))
    for ex in burst_ex[:3]:
        A("- 连发示例：%s" % " / ".join(str(x)[:16] for x in ex))
    A("")

    A("### 3.2 主动 vs 回应\n")
    A("- 纯问句 %d 条（%.0f%%）：%s" % (len(ask_msgs),
                                      100.0 * len(ask_msgs) / n_txt,
                                      "偏向主动追问" if len(ask_msgs) / n_txt > 0.12 else "以回应为主"))
    for t in ask_msgs[:5]:
        A("  - > %s" % t[:80].replace("\n", " "))
    A("")

    A("### 3.3 表态方式：缓冲与弱化\n")
    A("- 含 `我觉得/我感觉/可能/应该/其实/有点/好像` 等缓冲语的消息 **%d 条（%.0f%%）**。"
      % (len(hedge_msgs), 100.0 * len(hedge_msgs) / n_txt))
    for t in hedge_msgs[:5]:
        A("  - > %s" % t[:100].replace("\n", " "))
    A("")

    A("### 3.4 同意与附和的写法\n")
    A("- 典型短应答 %d 条：" % len(agree_msgs))
    A("  - %s" % "、".join("`%s`" % t for t in list(dict.fromkeys(agree_msgs))[:14]))
    A("")

    A("### 3.5 情绪表达（网络用语/粗口）\n")
    A("- 出现 %d 条（%.1f%%）：" % (len(slang_msgs), 100.0 * len(slang_msgs) / n_txt))
    for t in slang_msgs[:5]:
        A("  - > %s" % t[:90].replace("\n", " "))
    A("")

    A("## 四、话题与内容取向\n")
    A("### 4.1 高频片段（≥8 次）\n")
    top = [(f, c) for f, c in frag.most_common(40) if c >= 8][:20]
    A("| 片段 | 次数 | 片段 | 次数 |")
    A("|---|---|---|---|")
    for i in range(0, len(top) - 1, 2):
        A("| `%s` | %d | `%s` | %d |" % (top[i][0], top[i][1], top[i + 1][0], top[i + 1][1]))
    A("")
    A("### 4.2 长文本样本（认真表达时的语体）\n")
    for t in long_own[4:9]:
        A("- > %s%s" % (t[:200].replace("\n", " "), "…" if len(t) > 200 else ""))
    A("")
    if quoted:
        A("### 4.3 引用/转发文本（需剔除）\n")
        A("- 有 **%d 条**以引用他人或 AI 生成文本开头（如占卜合盘解读、活动通知），"
          "长度远高于其平均句长，做语体分析时必须排除。" % len(quoted))
        for t in quoted[:2]:
            A("  - > %s%s" % (t[:120].replace("\n", " "), "…" if len(t) > 120 else ""))
        A("")

    A("## 五、时间行为\n")
    A("### 5.1 活跃时段\n")
    A("| 时段 | 条数 |")
    A("|---|---|")
    for h in range(24):
        c = hours.get(h, 0)
        if c:
            A("| %02d:00–%02d:59 | %d |" % (h, h, c))
    A("")
    A("### 5.2 月度分布\n")
    A("| 月份 | 条数 |")
    A("|---|---|")
    for m, c in sorted(months.items()):
        A("| %s | %d |" % (m, c))
    A("")

    A("## 六、可操作结论\n")
    A("1. **句长**：以 **%d–%d 字**为宜（中位 %d），一条只说一件事。"
      % (max(1, sorted(lens)[len(lens) // 4]), sorted(lens)[int(len(lens) * 0.75)],
         sorted(lens)[len(lens) // 2]))
    A("2. **标点**：句末基本不加标点（含标点仅 %.0f%%），语气交给语气词与表情。"
      % (100.0 * sum(1 for t in texts if any(c in t for c in PUNCT)) / n_txt))
    A("3. **语气词**：高频使用 %s。"
      % "、".join("`%s`" % p for p, _ in sorted(
          ((p, sum(1 for t in texts if p in t)) for p in FILLERS),
          key=lambda x: -x[1])[:5]))
    A("4. **表情标签**：%s 是常用收尾/情绪标记。"
      % "、".join("`%s`" % t for t, _ in tags.most_common(5)))
    A("5. **非文本占比 %.0f%%**：语音/表情是重要表达手段，不可只用文字还原。"
      % (100.0 * sum(1 for m in him if m["type_name"] != "文本") / max(1, len(him))))
    A("6. **高频固定搭配**：%s。"
      % "、".join("`%s`" % t for t, c in [(t, c) for t, c in whole.most_common(20) if c >= 5][:8]))
    A("7. **表态先缓冲**：`我觉得 / 可能 / 应该 / 其实` 等占 %.0f%%。"
      % (100.0 * len(hedge_msgs) / n_txt))
    A("8. **连发**：平均 %.1f 条/段，最长 %d 条 —— 连续短句而非合并长段。"
      % (sum(b) / max(1, len(b)), max(b) if b else 0))
    A("")

    A("## 附：统计明细\n")
    A("```json")
    A(json.dumps({
        "被分析者": name, "代词": TA,
        "消息数": {"本人": len(him), "文本(过滤后)": len(texts), "引用转发": len(quoted),
                   "对话总计": len(ms)},
        "长度": {"平均": round(sum(lens) / n_txt, 2),
                 "中位": sorted(lens)[len(lens) // 2] if lens else 0,
                 "P90": sorted(lens)[int(len(lens) * 0.9)] if lens else 0,
                 "最长": max(lens) if lens else 0},
        "连发": {"段数": len(b), "平均": round(sum(b) / max(1, len(b)), 2),
                 "最长": max(b) if b else 0},
        "表情标签top": tags.most_common(10),
        "整句重复top": [(t, c) for t, c in whole.most_common(15) if c >= 3],
        "活跃小时": dict(sorted(hours.items())),
        "非文本构成": collections.Counter(
            m["type_name"] for m in him if m["type_name"] != "文本").most_common(),
    }, ensure_ascii=False, indent=1))
    A("```")

    os.makedirs(args.out, exist_ok=True)
    base = args.label or re.sub(r"[^\w\u4e00-\u9fff]+", "_", name).strip("_") or "chat"
    path = os.path.join(args.out, "%s_表达方式分析.md" % base)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    # 原始消息留档（便于人工抽查）
    raw = os.path.join(args.out, "_%s_messages.txt" % base)
    with open(raw, "w", encoding="utf-8") as f:
        for m in him:
            f.write("%s\t%s\t%s\n" % (m["time"], m["type_name"], m["text"]))
    print("-> %s  (%d KB)" % (path, os.path.getsize(path) // 1024))
    print("-> %s  (原始消息留档)" % raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
