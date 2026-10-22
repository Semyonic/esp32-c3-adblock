// Runs the dashboard's own JavaScript, straight out of src/page.h, against a
// stubbed DOM. The live-tracker card keeps state between polls — counts per
// hostname, when each was last seen, how many blocks it has already counted —
// and that state is what goes wrong silently: a reboot restarts the device's
// counter, and a tab left open all day meets thousands of distinct hostnames.
// Neither shows up in a screenshot, so they are checked here.
//
//   node tools/test_page.js
//
// Not strict mode on purpose: under 'use strict' the page's own function and
// `let` declarations would stay trapped inside the eval below.
const fs = require('fs');
const path = require('path');

const page = fs.readFileSync(path.join(__dirname, '..', 'src', 'page.h'), 'utf8');
const m = page.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.error('no <script> block in src/page.h'); process.exit(1); }
const src = m[1];

// --- the smallest DOM the page will run against
const els = {};
const mk = id => els[id] || (els[id] = {
  id, textContent: '', innerHTML: '', className: '', style: {}, value: '',
  setAttribute() {}, addEventListener() {}, closest() { return null; }, focus() {}
});
global.document = { getElementById: mk, addEventListener() {}, activeElement: null,
                    querySelectorAll: () => [], body: mk('body') };
global.window = global;
global.fetch = () => Promise.reject(new Error('offline'));
global.setInterval = () => 0;        // the 3 s refresh would hold the process open
global.setTimeout = () => 0;
// The page reaches for its elements by bare id, the way a browser exposes them.
for (const id of new Set(src.match(/\b[a-zA-Z][a-zA-Z0-9]*(?=\.(textContent|innerHTML|className|style|value|setAttribute))/g) || []))
  if (!(id in global)) global[id] = mk(id);

// eval is deliberate and safe here: the only thing evaluated is this repo's own
// src/page.h, read from disk beside this file — never input from a device or the
// network. It is what lets the page's own `let` bindings stay reachable, and the
// appended getters are the only way to see the accumulator state from out here.
eval(src + ';global.__cnt=()=>cnt;global.__last=()=>last');

let failed = 0;
const ok = (cond, what) => { console.log((cond ? '  PASS  ' : '  FAIL  ') + what); if (!cond) failed++; };
// `s` is the age in seconds the device reports for a block. Freshness has to
// come from that, not from how fast this loop happens to run, or the tie-break
// below would depend on the wall clock and fail whenever a batch lands inside
// one millisecond.
const feed = (hits, names, s = 1) =>
  trackers({ hits, recent: names.map(n => ({ n, c: '192.168.1.7', s })) });

// --- an ordinary run
feed(3, ['doubleclick.net', 'criteo.com', 'doubleclick.net']);
ok(/doubleclick\.net/.test(tags.innerHTML), 'counts the hostnames it was handed');
ok(/Google/.test(corp.innerHTML), 'groups doubleclick.net under its owner');
const beforeReboot = tags.innerHTML;

// --- the device reboots, so `hits` restarts below the total already counted
feed(2, ['analytics.tiktok.com', 'analytics.tiktok.com']);
ok(/tiktok/.test(tags.innerHTML), 'keeps counting after a reboot restarts hits');
ok(!/doubleclick/.test(tags.innerHTML), "drops the previous run's counts");
ok(tags.innerHTML !== beforeReboot, 'the card does not freeze');

// --- a tab left open across thousands of distinct hostnames
for (let i = 0; i < 4000; i++) feed(3 + i, ['h' + i + '.example.com'], 30);
const keys = Object.keys(global.__cnt()).length;
ok(keys <= 96, 'state stays bounded: ' + keys + ' hostnames held after 4000 distinct ones');
ok(Object.keys(global.__last()).length === keys, 'the freshness table holds the same keys');

// --- a fresh block outranks equally-counted older ones
feed(4100, ['criteo.com'], 0);
ok(/criteo\.com/.test(tags.innerHTML), 'a new block is drawn even when every count ties');

// --- the whole page, against the demo data it ships with
render(demodata());
ok(/alan adı/.test(corp.innerHTML), 'the whole page renders against its demo data');

console.log(failed ? '\n' + failed + ' page test(s) FAILED' : '\nall page tests passed');
process.exit(failed ? 1 : 0);
