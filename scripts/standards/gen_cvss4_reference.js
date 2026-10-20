// Generate CVSS v4.0 reference scores by running FIRST's official calculator
// code (FIRSTdotorg/cvss-v4-calculator) in a sandboxed vm context.
// Usage: node gen_cvss4_reference.js <calculator_src_dir> <first_examples.json> <out.tsv>
// <first_examples.json>: {vector: score} scraped from the v4.0 column of the
// table on https://www.first.org/cvss/v4.0/examples (first_cvss4_examples.json).
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const [srcDir, examplesPath, outPath] = process.argv.slice(2);
const ctx = vm.createContext({ console });
for (const f of ["metrics.js", "cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js"]) {
  vm.runInContext(fs.readFileSync(path.join(srcDir, f), "utf8"), ctx, { filename: f });
}

// Mirrors app.js resetSelected + setButtonsToVector (strict order check).
function parse(vector) {
  const order = ctx.expectedMetricOrder;
  const selected = {};
  for (const k of Object.keys(order)) selected[k] = k in { AV: 1, AC: 1, AT: 1, PR: 1, UI: 1, VC: 1, VI: 1, VA: 1, SC: 1, SI: 1, SA: 1 } ? null : "X";
  const parts = vector.split("/");
  if (parts[0] !== "CVSS:4.0") return null;
  parts.shift();
  const entries = Object.entries(order);
  let oi = 0;
  for (const p of parts) {
    const [key, value] = p.split(":");
    let expected = entries[oi++];
    while (true) {
      if (expected === undefined) return null;
      if (key !== expected[0]) {
        if (oi <= 11) return null;
        expected = entries[oi++];
        continue;
      }
      break;
    }
    if (!expected[1].includes(value)) return null;
    selected[key] = value;
  }
  for (const k of ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]) if (selected[k] === null) return null;
  return selected;
}

function score(vector) {
  const sel = parse(vector);
  if (!sel) return null;
  ctx.__sel = sel;
  const mv = vm.runInContext("macroVector(__sel)", ctx);
  ctx.__mv = mv;
  const s = vm.runInContext("cvss_score(__sel, cvssLookup_global, maxSeverity, __mv)", ctx);
  return { macro_vector: mv, score: s };
}

// Deterministic PRNG (mulberry32) so the fixture is reproducible.
function rng(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const r = rng(20261020);
const pick = (arr) => arr[Math.floor(r() * arr.length)];
const order = ctx.expectedMetricOrder;
const base = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
const env = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"];
function randomVector(withE, envProb) {
  let v = "CVSS:4.0";
  for (const k of base) v += `/${k}:${pick(order[k])}`;
  if (withE) {
    const e = pick(order.E);
    if (e !== "X") v += `/E:${e}`;
  }
  for (const k of env) {
    if (r() < envProb) {
      const val = pick(order[k].filter((x) => x !== "X"));
      v += `/${k}:${val}`;
    }
  }
  return v;
}

const examples = JSON.parse(fs.readFileSync(examplesPath, "utf8"));
const out = { first_examples: [], generated: [] };
for (const [vector, published] of Object.entries(examples)) {
  const s = score(vector);
  out.first_examples.push({ vector, published_score: published, calculator_score: s && s.score, macro_vector: s && s.macro_vector });
}
const seen = new Set();
function add(v) {
  if (seen.has(v)) return;
  seen.add(v);
  const s = score(v);
  if (!s) throw new Error("generated invalid vector " + v);
  out.generated.push({ vector: v, score: s.score, macro_vector: s.macro_vector });
}
while (out.generated.length < 400) add(randomVector(false, 0));
while (out.generated.length < 600) add(randomVector(true, 0));
while (out.generated.length < 800) add(randomVector(true, 0.3));
const lines = [
  "# CVSS v4.0 reference scores for crates/vettalon/src/audit/cvss4.rs tests.",
  "# Generated 2026-10-20 by scripts/standards/gen_cvss4_reference.js, which runs FIRST's",
  "# official calculator code (github.com/FIRSTdotorg/cvss-v4-calculator @ c5b0d409ae9f57c44264c6ce5f27d89298e1d32a,",
  "# BSD-2-Clause, Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors).",
  "# example  = vector/score pairs from the table on https://www.first.org/cvss/v4.0/examples (fetched 2026-10-20)",
  "#            whose published score the official calculator reproduces;",
  "# invalid  = vectors printed on that page out of the Table 23 order (spec: \"every other ordering is invalid\");",
  "# calc     = deterministic pseudo-random vectors (seed 20261020) scored by the official calculator.",
  "# kind<TAB>vector<TAB>score",
];
for (const e of out.first_examples) {
  if (e.calculator_score === null) lines.push(`invalid\t${e.vector}\t-`);
  else if (e.calculator_score === e.published_score) lines.push(`example\t${e.vector}\t${e.published_score.toFixed(1)}`);
}
const g = out.generated;
for (const e of [...g.slice(0, 150), ...g.slice(400, 475), ...g.slice(600, 675)]) lines.push(`calc\t${e.vector}\t${e.score.toFixed(1)}`);
fs.writeFileSync(outPath, lines.join("\n") + "\n");
const mism = out.first_examples.filter((e) => e.calculator_score !== e.published_score);
console.log("examples", out.first_examples.length, "not reproduced (layout artefacts or invalid order):", mism.length);
