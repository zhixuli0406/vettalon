// Writes the license inventory of this image to stdout: every Debian
// package, every npm package under the global node_modules, Node.js itself
// and the native programs bundled inside the codex npm package. Runs once at
// build time; the result is /usr/share/licenses/INVENTORY.txt.
'use strict';
const fs = require('fs');
const path = require('path');

const out = [];
const line = (s = '') => out.push(s);

function read(p) {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return null;
  }
}

// Debian: /var/lib/dpkg/status, licenses from machine-readable copyright
// files (DEP-5) when present, otherwise a pointer to the copyright file.
function debianPackages() {
  const status = read('/var/lib/dpkg/status') || '';
  const pkgs = [];
  for (const stanza of status.split(/\n\n+/)) {
    const f = {};
    for (const m of stanza.matchAll(/^([A-Za-z-]+): (.*)$/gm)) f[m[1]] = m[2];
    if (!f.Package || !/ installed$/.test(f.Status || '')) continue;
    pkgs.push(f);
  }
  pkgs.sort((a, b) => a.Package.localeCompare(b.Package));
  for (const p of pkgs) {
    const copyright = `/usr/share/doc/${p.Package}/copyright`;
    const text = read(copyright);
    let lic = `see ${copyright}`;
    if (text && /^Format: .*copyright-format/m.test(text)) {
      const names = new Set();
      for (const m of text.matchAll(/^License: *(\S.*)$/gm)) names.add(m[1].trim());
      if (names.size) lic = `${[...names].join('; ')} (${copyright})`;
    } else if (!text) {
      lic = 'copyright file missing';
    }
    const src = (p.Source || p.Package).split(' ')[0];
    line(`deb\t${p.Package}\t${p.Version}\tsource=${src}\t${lic}`);
  }
}

// npm: every package.json under the global node_modules (npm and codex,
// with their bundled dependencies).
function npmPackages(root) {
  const seen = new Set();
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink()) continue;
      const p = path.join(dir, e.name);
      if (e.name.startsWith('@')) {
        walk(p);
        continue;
      }
      const pj = read(path.join(p, 'package.json'));
      if (pj) {
        try {
          const j = JSON.parse(pj);
          if (j.name && j.version) {
            const lic = typeof j.license === 'string' ? j.license : JSON.stringify(j.license || j.licenses || 'UNKNOWN');
            const key = `${j.name}@${j.version}`;
            if (!seen.has(key)) {
              seen.add(key);
              line(`npm\t${j.name}\t${j.version}\t${lic}\t${p}`);
            }
          }
        } catch {
          line(`npm\t?\t?\tunreadable package.json\t${p}`);
        }
      }
      walk(path.join(p, 'node_modules'));
    }
  };
  walk(root);
}

// Native programs shipped inside the codex platform package.
function codexNative(root) {
  const vendors = [];
  const findVendor = (dir, depth) => {
    if (depth > 6) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const p = path.join(dir, e.name);
      if (e.name === 'vendor' && fs.existsSync(p)) {
        for (const t of fs.readdirSync(p)) {
          if (fs.existsSync(path.join(p, t, 'codex-package.json'))) vendors.push(path.join(p, t));
        }
      } else {
        findVendor(p, depth + 1);
      }
    }
  };
  findVendor(root, 0);
  if (!vendors.length) throw new Error('codex platform package not found');
  for (const v of vendors) {
    const pkg = JSON.parse(read(path.join(v, 'codex-package.json')));
    line(`codex\tcodex\t${pkg.version}\tApache-2.0 (/usr/share/licenses/codex/)\t${v}/bin`);
    line(`codex\tripgrep (rg)\t-\tUnlicense OR MIT\t${v}/codex-path/rg`);
    line(`codex\tbubblewrap (bwrap)\t-\tLGPL-2.0-or-later (/usr/share/licenses/codex-bwrap/COPYING; source in the -source artifact)\t${v}/codex-resources/bwrap`);
    line(`codex\tzsh\t-\tzsh licence (/usr/share/licenses/codex-zsh/LICENCE)\t${v}/codex-resources/zsh`);
    const sources = read(path.join(v, 'codex-resources/voice/sources.json'));
    if (sources) {
      for (const s of JSON.parse(sources).sources) {
        if (s.role === 'build-tool') continue;
        line(`codex-voice\t${s.name}\t${s.version}\tsee ${v}/codex-resources/voice/NOTICE.md and licenses/ (source in the -source artifact)\t${s.url}`);
      }
    }
  }
}

line('# License inventory of the vettalon-agents-base image.');
line('# Corresponding source for the GPL/LGPL components is published next to');
line('# this image as the OCI artifact tagged <image tag>-source (see docs/TRUST.md).');
line('# Columns: kind, name, version, license, location');
line();
line(`node\tnode\t${process.version}\tMIT and bundled licenses (/usr/share/licenses/node/LICENSE)\t/usr/local/bin/node`);
debianPackages();
npmPackages('/usr/local/lib/node_modules');
codexNative('/usr/local/lib/node_modules/@openai/codex');
process.stdout.write(out.join('\n') + '\n');
