"""依赖自举：优先用系统安装的包，缺失时回退到项目自带的 lib/。

两种情况都能跑：
    python -m wxarchive info                    # 系统已装 pycryptodome
    python -m wxarchive info                    # 未装 → 自动使用 <项目根>/lib 内的副本
"""
import os
import sys

VENDOR_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")


def ensure_dep(module_name, hint=None):
    """确保 module_name 可导入；缺失时尝试把项目 lib/ 加入 sys.path。"""
    try:
        __import__(module_name)
        return True
    except ImportError:
        pass
    if os.path.isdir(VENDOR_LIB) and VENDOR_LIB not in sys.path:
        sys.path.append(VENDOR_LIB)
        try:
            __import__(module_name)
            return True
        except ImportError:
            pass
    print("[依赖缺失] 无法导入 %s。请执行：pip install %s"
          % (module_name, hint or module_name), file=sys.stderr)
    return False
