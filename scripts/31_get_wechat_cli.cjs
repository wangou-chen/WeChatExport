// 从清华 PyPI 镜像下载 wechat-cli wheel 并解包到 lib\wechat_cli_pkg
// 用法: node 31_get_wechat_cli.cjs
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const MIRROR = 'https://pypi.tuna.tsinghua.edu.cn/simple/wechat-cli/';
const DL = path.join(__dirname, '..', 'download');
const LIB = path.join(__dirname, '..', 'lib', 'wechat_cli_pkg');

function findEOCD(buf) {
  for (let i = buf.length - 22; i >= 0 && i > buf.length - 70000; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) return i;
  }
  return -1;
}

function unzip(buf, lib) {
  fs.mkdirSync(lib, { recursive: true });
  const eocd = findEOCD(buf);
  if (eocd < 0) throw new Error('不是有效 zip');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  let n = 0;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const lho = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    const lnameLen = buf.readUInt16LE(lho + 26);
    const lextraLen = buf.readUInt16LE(lho + 28);
    const dataStart = lho + 30 + lnameLen + lextraLen;
    if (name.endsWith('/')) {
      fs.mkdirSync(path.join(lib, name), { recursive: true });
    } else {
      const raw = buf.subarray(dataStart, dataStart + csize);
      const out = method === 0 ? raw : zlib.inflateRawSync(raw);
      const dest = path.join(lib, name);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, out);
      n++;
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  return n;
}

async function main() {
  const r = await fetch(MIRROR, { headers: { 'User-Agent': 'dsh' } });
  const html = await r.text();
  const links = [...html.matchAll(/href="([^"]+\.whl[^"]*)"/g)].map((m) => m[1]);
  if (!links.length) throw new Error('镜像上没有 wechat-cli wheel');
  const pick = links[links.length - 1];
  const url = new URL(pick.replace(/#.*$/, ''), MIRROR).toString();
  console.log('picked', url);
  const resp = await fetch(url, { headers: { 'User-Agent': 'dsh' } });
  if (!resp.ok) throw new Error('下载失败 ' + resp.status);
  const buf = Buffer.from(await resp.arrayBuffer());
  fs.mkdirSync(DL, { recursive: true });
  const whl = path.join(DL, path.basename(new URL(url).pathname));
  fs.writeFileSync(whl, buf);
  console.log('saved', whl, (buf.length / 1024).toFixed(0) + 'KB');
  const n = unzip(buf, LIB);
  console.log('extracted', n, 'files ->', LIB);
}
main().catch((e) => { console.error('ERR', e.message); process.exit(1); });
