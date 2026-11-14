import fs from 'node:fs';
import path from 'node:path';
export function run(x) {
  const base = process.env.VTL_BASE;
  return fs.readFileSync(path.join(base, x), 'utf8');
}
