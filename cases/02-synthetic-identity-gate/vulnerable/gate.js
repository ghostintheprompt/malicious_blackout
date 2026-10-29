// VULNERABLE: the gate trusts the claimed identity and issues a session without
// ever testing whether the sample is live. A clone is as good as a face. This is
// where the attacker crosses the trust boundary and becomes an authenticated
// insider, holding a real session the rest of the swarm will believe.

function createGate() {
  const log = { presentationAttacks: [] };
  function verify(sample) {
    if (!sample) return { ok: false, reason: 'no sample' };
    return { ok: true, session: { role: sample.claimedRole, subject: sample.subject } };
  }
  return { verify, log };
}

module.exports = { createGate };
