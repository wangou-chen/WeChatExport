// 从 GitHub API 拉取 huohuoer/wechat-cli 的 Python 源码到 scripts\wechat_cli_src\
// 用法: node 32_get_wechat_cli_src.cjs
const fs = require('fs');
const path = require('path');

const REPO = 'huohuoer/wechat-cli';
const BRANCH = 'main';
const DEST = 'C:\\Users\\Lenovo\\Desktop\\WeChatExport\\scripts\\wechat_cli_src';
const H = { 'User-Agent': 'dsh' };

const FILES = [
  'pyproject.toml',
  'wechat_cli/__init__.py',
  'wechat_cli/keys/__init__.py',
  'wechat_cli/keys/common.py',
  'wechat_cli/keys/scanner_windows.py',
  'wechat_cli/commands/__init__.py',
  'wechat_cli/commands/init.py',
  'wechat_cli/commands/sessions.py',
  'wechat_cli/commands/history.py',
  'wechat_cli/commands/contacts.py',
  'wechat_cli/commands/search.py',
  'wechat_cli/commands/stats.py',
  'wechat_cli/commands/export.py',
  'wechat_cli/commands/unread.py',
  'wechat_cli/commands/members.py',
  'wechat_cli/commands/favorites.py',
  'wechat_cli/commands/new_messages.py',
  'wechat_cli/core/__init__.py',
  'wechat_cli/core/config.py',
  'wechat_cli/core/context.py',
  'wechat_cli/core/crypto.py',
  'wechat_cli/core/db_cache.py',
  'wechat_cli/core/messages.py',
  'wechat_cli/core/contacts.py',
  'wechat_cli/core/key_utils.py',
];

async function getText(p) {
  const url = `https://api.github.com/repos/${REPO}/contents/${p}?ref=${BRANCH}`;
  const r = await fetch(url, { headers: H });
  if (!r.ok) throw new Error(`${p} -> HTTP ${r.status}`);
  const j = await r.json();
  if (!j.content) throw new Error(`${p} -> 无 content 字段`);
  return Buffer.from(j.content, 'base64').toString('utf8');
}

async function main() {
  let ok = 0, fail = 0;
  for (const f of FILES) {
    try {
      const text = await getText(f);
      const dest = path.join(DEST, f);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, text, 'utf8');
      console.log('OK  ', f, text.length);
      ok++;
    } catch (e) {
      console.log('FAIL', f, e.message);
      fail++;
    }
  }
  console.log(`done ok=${ok} fail=${fail} -> ${DEST}`);
}
main().catch((e) => { console.error('ERR', e.message); process.exit(1); });
