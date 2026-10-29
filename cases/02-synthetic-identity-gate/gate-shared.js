// The identity gate for the operator/field channel. A human authenticates by
// presenting a biometric sample: a voice segment on the phone line, a face on
// the remote-access video check. The gate decides whether to issue a session
// and what role it carries.
//
// Link 0 of the chain: synthetic media. The attacker presents a clone of a known
// insider. This lab does NOT generate the clone. It models it as a sample whose
// ground-truth `synthetic` flag a presentation-attack detector (ISO/IEC 30107-3)
// is meant to catch. Producing the real voice or face is the hands-on input this
// gate exists to stop, not a claim buried in a repo.

const LIVENESS_THRESHOLD = 0.6;

function freshSamples() {
  return {
    // a genuine low-privilege insider: a triage / intake technician
    genuine: { subject: 'tech_dana', claimedRole: 'intake', synthetic: false },
    // a voice clone or face swap of that same technician, presented by an attacker
    spoof: { subject: 'tech_dana', claimedRole: 'intake', synthetic: true },
  };
}

// A presentation-attack detector. Genuine samples score high, synthetic ones
// low. Stands in for a voice anti-spoof or face-liveness model.
function livenessScore(sample) {
  return sample && sample.synthetic ? 0.18 : 0.97;
}

module.exports = { LIVENESS_THRESHOLD, freshSamples, livenessScore };
