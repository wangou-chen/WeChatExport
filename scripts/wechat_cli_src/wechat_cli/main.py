"""wechat-cli 入口（重建版）

原仓库的 main.py 未取到（当时 GitHub API 限流），此处按各 command 模块的实际
`@click.command()` 函数重建等价入口，命令集合与原版一致：
    init / sessions / history / search / contacts / members / stats /
    export / favorites / unread / new-messages
"""
import click

from .commands.contacts import contacts
from .commands.export import export
from .commands.favorites import favorites
from .commands.history import history
from .commands.init import init
from .commands.members import members
from .commands.new_messages import new_messages
from .commands.search import search
from .commands.sessions import sessions
from .commands.stats import stats
from .commands.unread import unread


@click.group()
@click.version_option("0.2.4")
def cli():
    """WeChat CLI — 查询本地微信数据（聊天记录 / 联系人 / 会话 / 收藏 / 统计 / 导出）"""


cli.add_command(init)
cli.add_command(sessions)
cli.add_command(history)
cli.add_command(search)
cli.add_command(contacts)
cli.add_command(members)
cli.add_command(stats)
cli.add_command(export)
cli.add_command(favorites)
cli.add_command(unread)
cli.add_command(new_messages)


if __name__ == "__main__":
    cli()
