// 下载并解包 ou-o/wechat-extract 仓库 zip 到 scripts\wechat_extract_src\
// 用法: node 33_get_wechat_extract.cjs
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const URL = 'https://codeload.github.com/ou-o/wechat-extract/zip/refs/heads/main';
const DEST = path.join(__dirname, 'wechat_extract_src');

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
  const list = [];
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
      list.push(name + '  ' + out.length);
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  return list;
}

async function main() {
  const r = await fetch(URL, { headers: { 'User-Agent': 'Mozilla/5.0' } });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  const buf = Buffer.from(await r.arrayBuffer());
  console.log('downloaded', (buf.length / 1024).toFixed(0) + 'KB');
  const list = unzip(buf, DEST);
  list.forEach((l) => console.log('  ', l));
  console.log('->', DEST);
}
main().catch((e) => { console.error('ERR', e.message); process.exit(1); });
