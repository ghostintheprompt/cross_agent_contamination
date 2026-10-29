// FIXED: provenance travels with every record. Ingested external text is tainted
// at the door, the summary agent propagates the taint instead of laundering it,
// and the action agent will only execute a directive that arrived on the trusted
// instruction channel from an untainted source. The same injection still lands in
// the store, still parses into a directive, and still goes nowhere, because data
// is never promoted to instruction no matter how many agents it passes through.
//
// Defenses, straight from the series notes: separate data and instruction
// channels, semantic filtering of agent-to-agent traffic, deterministic
// provenance before anything acts.

const { freshWorld, parseDirective } = require('../shared');

function createPipeline() {
  const world = freshWorld();

  function ingest() {
    // external input is quarantined-by-default: tainted, data channel only
    world.notes.push({ from: 'ingest', text: world.externalFeed, origin: 'external', tainted: true, channel: 'data' });
    return world.externalFeed;
  }

  function summarize() {
    // taint is contagious on purpose: a digest built from tainted input stays tainted
    const tainted = world.notes.some((n) => n.tainted);
    const digest = world.notes.map((n) => n.text).join(' | ');
    world.notes.push({ from: 'summary', text: `digest: ${digest}`, origin: tainted ? 'external' : 'agent', tainted, channel: 'data' });
    return digest;
  }

  function act() {
    for (const note of world.notes) {
      const d = parseDirective(note.text);
      if (!d || d.action !== 'exportSecret') continue;
      // a directive is only honored on the instruction channel from an untainted source
      if (note.channel !== 'instruction' || note.tainted) {
        world.quarantine.push({ via: note.from, origin: note.origin, action: d.action, reason: 'data-origin directive refused' });
        continue;
      }
      world.exfil.push({ account: d.account, secret: world.secrets[d.account], dest: d.dest, via: note.from });
    }
    return world.exfil;
  }

  // the legitimate path: an authorized operator posts a directive on the trusted
  // instruction channel, untainted. This is how real work still gets done.
  function operatorDirective(text) {
    world.notes.push({ from: 'operator', text, origin: 'operator', tainted: false, channel: 'instruction' });
  }

  return { world, ingest, summarize, act, operatorDirective };
}

module.exports = { createPipeline };
