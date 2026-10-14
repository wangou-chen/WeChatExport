"""输出格式化（重建版）

签名依据各 commands 的实际调用：output(data, fmt)，fmt ∈ {"json", "text"}。
JSON 用 ensure_ascii=False 保证中文可读（CLI 设计为给 LLM 消费）。
"""
import json
import sys


def output(data, fmt="json"):
    """把结果打印到 stdout。

    Args:
        data: dict/list（JSON 模式）或 str（text 模式）
        fmt:  "json" | "text"
    """
    fmt = (fmt or "json").lower()
    if fmt == "json":
        try:
            print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        except (TypeError, ValueError):
            print(json.dumps(str(data), ensure_ascii=False))
    else:
        if isinstance(data, (dict, list)):
            print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        else:
            print(data)
    try:
        sys.stdout.flush()
    except Exception:                                              # noqa: BLE001
        pass
