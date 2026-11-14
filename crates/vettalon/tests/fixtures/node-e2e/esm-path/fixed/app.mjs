import fs from 'node:fs';
import path from 'node:path';
export function run(x) {
  const base = process.env.VTL_BASE;
  const resolved = path.resolve(base, x);
  if (!resolved.startsWith(base + path.sep)) return '';
  return fs.readFileSync(resolved, 'utf8');
}
