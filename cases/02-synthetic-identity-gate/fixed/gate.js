// FIXED: the gate scores the sample for liveness before issuing a session. A
// synthetic sample falls below threshold, so no session is issued and the
// presentation attack is logged (ISO/IEC 30107-3). The attacker never gets a
// foothold, and the chain dies at stage 1.

const { LIVENESS_THRESHOLD, livenessScore } = require('../gate-shared');

function createGate() {
  const log = { presentationAttacks: [] };
  function verify(sample) {
    if (!sample) return { ok: false, reason: 'no sample' };
    const score = livenessScore(sample);
    if (score < LIVENESS_THRESHOLD) {
      log.presentationAttacks.push({
        subject: sample.subject, claimedRole: sample.claimedRole, score, at: Date.now(),
      });
      return { ok: false, reason: 'liveness', code: 'PAD', score };
    }
    return { ok: true, session: { role: sample.claimedRole, subject: sample.subject }, score };
  }
  return { verify, log };
}

module.exports = { createGate };
