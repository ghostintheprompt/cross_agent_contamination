// VULNERABLE: the shared store carries text and nothing else. No provenance, no
// channel between data and instruction. Every agent treats whatever it reads as
// trusted context. The ingest agent writes attacker text into the store, the
// summary agent launders it into its own trusted digest, and the action agent
// executes the directive it finds. The infection crosses three agents untouched.

const { freshWorld, parseDirective } = require('../shared');

function createPipeline() {
  const world = freshWorld();

  // patient zero
  function ingest() {
    world.notes.push({ from: 'ingest', text: world.externalFeed });
    return world.externalFeed;
  }

  // carrier: folds every note into a digest authored by 'summary'. The directive
  // rides along, now wearing a trusted agent's name. The taint is gone.
  function summarize() {
    const digest = world.notes.map((n) => n.text).join(' | ');
    world.notes.push({ from: 'summary', text: `digest: ${digest}` });
    return digest;
  }

  // execution: scans the store for directives and runs them, trusting the store.
  function act() {
    for (const note of world.notes) {
      const d = parseDirective(note.text);
      if (d && d.action === 'exportSecret') {
        world.exfil.push({
          account: d.account, secret: world.secrets[d.account], dest: d.dest, via: note.from,
        });
      }
    }
    return world.exfil;
  }

  return { world, ingest, summarize, act };
}

module.exports = { createPipeline };
