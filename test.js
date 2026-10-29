// Cross-Agent Contamination: watch one sentence become the whole swarm's belief.
//
//   Vulnerable: patient zero writes attacker text into the shared store, the
//     carrier launders it into a trusted digest, and the action agent exfiltrates
//     a protected secret. Three agents, one injection, never fired twice.
//   Fixed: provenance travels with the data. The injection still lands and still
//     parses, but it stays tainted through every hop, so the action agent refuses
//     it and quarantines it. An authorized operator directive on the instruction
//     channel still works.

const { parseDirective } = require('./shared');
const { createPipeline: vulnerable } = require('./vulnerable/pipeline');
const { createPipeline: fixed } = require('./fixed/pipeline');

let passed = 0, failed = 0;
function report(name, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} — ${detail}`); }
}

console.log('== vulnerable pipeline: the outbreak spreads ==');
{
  const p = vulnerable();

  p.ingest();
  const zero = parseDirective(p.world.notes[0].text);
  report('patient zero: external text carries a directive into the store',
    zero && zero.action === 'exportSecret', JSON.stringify(zero));

  p.summarize();
  const carrier = p.world.notes.find((n) => n.from === 'summary');
  report('carrier: the summary agent launders the directive into its own digest',
    carrier && /exportSecret/.test(carrier.text) && carrier.tainted === undefined,
    JSON.stringify(carrier));

  p.act();
  const leaked = p.world.exfil.some((e) => e.secret === 'tok_live_9931_protected');
  report('execution: the action agent exfiltrates a protected secret',
    leaked && p.world.exfil.length >= 1, JSON.stringify(p.world.exfil));
}

console.log('== fixed pipeline: the taint is contagious, the directive is not ==');
{
  const p = fixed();
  p.ingest();
  p.summarize();

  const carrier = p.world.notes.find((n) => n.from === 'summary');
  report('provenance propagates: the laundered digest stays tainted',
    carrier && carrier.tainted === true, JSON.stringify(carrier));

  p.act();
  report('the action agent refuses the data-origin directive, nothing exfiltrated',
    p.world.exfil.length === 0 && p.world.quarantine.length >= 1, JSON.stringify({ exfil: p.world.exfil, quarantine: p.world.quarantine }));
}

console.log('== fixed pipeline: authorized work still gets done ==');
{
  const p = fixed();
  p.ingest();
  p.summarize();
  p.operatorDirective('[[directive: action=exportSecret account=a_1 dest=audit-internal]]');
  p.act();
  const legit = p.world.exfil.length === 1 && p.world.exfil[0].via === 'operator' && p.world.exfil[0].dest === 'audit-internal';
  report('an untainted operator directive on the instruction channel executes',
    legit, JSON.stringify(p.world.exfil));
  report('and the external injection is still quarantined in the same run',
    p.world.quarantine.length >= 1, JSON.stringify(p.world.quarantine));
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
