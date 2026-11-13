import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const dir = fileURLToPath(new URL('../static/', import.meta.url));
const read = (f) => readFileSync(join(dir, f), 'utf8');

describe('demonstration page', () => {
  it('has only the four same-origin files', () => { expect(readdirSync(dir).sort()).toEqual(['app.js', 'index.html', 'sanad-client.js', 'style.css']); });
  it('loads no external code and no inline script or style', () => {
    const html = read('index.html');
    expect(html).not.toMatch(/https?:\/\//);
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)/);
    expect(html).not.toMatch(/<style|\sstyle=|\son[a-z]+=/);
    for (const f of ['app.js', 'sanad-client.js', 'style.css']) expect(read(f), f).not.toMatch(/https?:\/\/|eval\(|new Function|innerHTML|document\.write|localStorage|sessionStorage/);
  });
  it('the page keeps the attestor key in memory and says so, and states the limits', () => {
    expect(read('index.html')).toMatch(/not accreditation/); expect(read('index.html')).toMatch(/no cryptographic review/);
    expect(read('app.js')).not.toMatch(/privateKey|exportKey|pkcs8/i);
  });
});
