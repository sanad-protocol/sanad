import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.xml': 'application/xml', '.txt': 'text/plain; charset=utf-8', '.pdf': 'application/pdf', '.json': 'application/json' };
export function serve(root = 'dist', port = 0) {
  return new Promise((res) => {
    const s = createServer((q, r) => {
      let p = decodeURIComponent(q.url.split('?')[0].split('#')[0]); let f = join(root, p);
      if (existsSync(f) && statSync(f).isDirectory()) f = join(f, 'index.html');
      if (!existsSync(f)) { const nf = join(root, '404.html'); r.writeHead(404, { 'content-type': TYPES['.html'] }); return r.end(existsSync(nf) ? readFileSync(nf) : 'not found'); }
      r.writeHead(200, { 'content-type': TYPES[extname(f)] || 'application/octet-stream' }); r.end(readFileSync(f));
    }).listen(port, '127.0.0.1', () => res({ url: `http://127.0.0.1:${s.address().port}`, close: () => s.close() }));
  });
}
