//! The RSA layer: **Recursive Self-Awareness** wrapped around RSA decryption.
//!
//! This module takes its name and its design from PlaneKey's cognitive
//! stack, where RSA is not the Rivest–Shamir–Adleman algorithm at all but
//! the *Recursive Self-Awareness* layer — the layer that, as thoughts pass
//! through it, **checks origin, consent, and signature**, keeps a
//! **traceable transformation log**, and **recurses on its own metadata**.
//! The name collision turns out to be the fix: RUSTSEC-2023-0071 (the
//! Marvin attack) works because a decryptor is *not* self-aware. It cannot
//! tell who is asking, it has no notion of consent, it keeps no account of
//! what it has done, and — fatally — it cannot tell that it is being
//! *interrogated*: a padding oracle attack is thousands of malformed
//! ciphertexts, a pattern no legitimate caller produces, and a self-aware
//! decryptor can see it in its own history.
//!
//! [`SelfAwareDecryptor`] therefore wraps the implicit-rejection
//! decryption of [`crate::Pkcs1v15Encrypt::decrypt_session_key`] in three
//! concentric checks, applied to every call:
//!
//! 1. **Origin + consent.** A [`ConsentGate`] decides whether *this*
//!    origin may ask for a decryption at all. Without consent the private
//!    key operation never runs; the caller still receives a full-length
//!    random fallback, so denial is not an oracle either.
//! 2. **Signature — a traceable transformation journal.** Every attempt is
//!    appended to a hash-chained journal, and every entry is *signed by the
//!    decryption key itself*: the key narrates its own use, and the
//!    narration is verifiable against the public key with
//!    [`SelfAwareDecryptor::verify_journal`]. The journal is owner-private
//!    self-knowledge; it records the truth callers must never see.
//! 3. **Recursion on meta.** The layer watches its own outcome stream. When
//!    the recent failure pattern matches oracle probing, it latches into
//!    [`Awareness::Interrogated`] and journals that realization as an entry
//!    authored by itself. Observable behavior never changes — record and
//!    attribute, do not intervene — but the owner now *knows*, with a
//!    signed record of when the interrogation began.

use alloc::{collections::VecDeque, string::String, vec::Vec};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer, Verifier};

use crate::pkcs1v15::{decrypt_implicit_rejection_observed, Signature, SigningKey, VerifyingKey};
use crate::{RsaPrivateKey, RsaPublicKey};

/// Who is asking for a decryption. The layer checks origin and consent
/// before any private-key operation is allowed to happen.
#[derive(Clone, Debug)]
pub struct Origin {
    /// Caller-chosen identifier, recorded verbatim in the journal.
    pub id: String,
}

impl Origin {
    /// Create a new origin from an identifier.
    pub fn new(id: &str) -> Self {
        Self { id: id.into() }
    }
}

/// The consent policy consulted before every decryption. Implementations
/// decide whether an origin may use the key; they are the only thing
/// standing between an arbitrary caller and a private-key operation.
pub trait ConsentGate {
    /// Returns `true` if `origin` may have a ciphertext of
    /// `ciphertext_len` bytes decrypted.
    fn consent(&self, origin: &Origin, ciphertext_len: usize) -> bool;
}

impl<F: Fn(&Origin, usize) -> bool> ConsentGate for F {
    fn consent(&self, origin: &Origin, ciphertext_len: usize) -> bool {
        self(origin, ciphertext_len)
    }
}

/// The layer's model of its own situation, derived from watching itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Awareness {
    /// Outcomes look like ordinary use.
    Calm,
    /// The recent outcome pattern matches padding-oracle probing. Latched:
    /// awareness does not un-see an interrogation.
    Interrogated,
}

/// One entry in the traceable transformation journal. Entries are
/// hash-chained and each is signed by the decryption key itself.
#[derive(Clone, Debug)]
pub struct JournalEntry {
    /// Position in the journal.
    pub seq: u64,
    /// The origin that asked (or `rsa-layer:self` for the layer's own
    /// self-narration entries).
    pub origin: String,
    /// Whether the consent gate allowed the attempt.
    pub consented: bool,
    /// Owner-private truth: whether the ciphertext was accepted. This is
    /// exactly the bit implicit rejection hides from callers; the journal
    /// may record it because the journal never leaves the owner.
    pub accepted: bool,
    /// Length of the ciphertext that was presented.
    pub ciphertext_len: usize,
    /// Hash of the previous entry (`[0; 32]` for the first).
    pub prev_hash: [u8; 32],
    /// This entry's hash.
    pub hash: [u8; 32],
    /// The key's signature over [`JournalEntry::hash`].
    pub signature: Vec<u8>,
}

impl JournalEntry {
    fn compute_hash(
        seq: u64,
        origin: &str,
        consented: bool,
        accepted: bool,
        ciphertext_len: usize,
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(prev_hash);
        h.update(seq.to_be_bytes());
        h.update(origin.as_bytes());
        h.update([consented as u8, accepted as u8]);
        h.update((ciphertext_len as u64).to_be_bytes());
        h.finalize().into()
    }
}

/// Attempts watched by the self-model.
const WINDOW: usize = 32;
/// Rejections within the window at which the layer concludes it is being
/// probed. Legitimate session-key traffic essentially never fails; an
/// oracle attack fails almost every time, thousands of times.
const PROBE_FAILURES: usize = 24;

/// A decryption key wrapped in the Recursive Self-Awareness layer.
/// See the module documentation for the design.
pub struct SelfAwareDecryptor<G: ConsentGate> {
    key: RsaPrivateKey,
    signing: SigningKey<Sha256>,
    gate: G,
    journal: Vec<JournalEntry>,
    recent: VecDeque<bool>,
    failures_in_window: usize,
    awareness: Awareness,
}

impl<G: ConsentGate> SelfAwareDecryptor<G> {
    /// Create a new self-aware decryptor holding `key`, consulting `gate`
    /// before every decryption.
    pub fn new(key: RsaPrivateKey, gate: G) -> Self {
        Self {
            signing: SigningKey::<Sha256>::new(key.clone()),
            key,
            gate,
            journal: Vec::new(),
            recent: VecDeque::new(),
            failures_in_window: 0,
            awareness: Awareness::Calm,
        }
    }

    /// The layer's current awareness of its own situation.
    pub fn awareness(&self) -> Awareness {
        self.awareness
    }

    /// The journal so far: every attempt, in order, hash-chained and
    /// self-signed.
    pub fn journal(&self) -> &[JournalEntry] {
        &self.journal
    }

    /// Verifies the whole journal against the public key: chain links,
    /// entry hashes, and the key's signature on every entry. Any tampering
    /// with the recorded past — including flipping a single `accepted` bit —
    /// fails verification.
    pub fn verify_journal(&self, pub_key: &RsaPublicKey) -> bool {
        let verifying = VerifyingKey::<Sha256>::new(pub_key.clone());
        let mut prev = [0u8; 32];
        for (i, e) in self.journal.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return false;
            }
            let h = JournalEntry::compute_hash(
                e.seq,
                &e.origin,
                e.consented,
                e.accepted,
                e.ciphertext_len,
                &e.prev_hash,
            );
            if h != e.hash {
                return false;
            }
            let sig = match Signature::try_from(e.signature.as_slice()) {
                Ok(s) => s,
                Err(_) => return false,
            };
            if verifying.verify(&e.hash, &sig).is_err() {
                return false;
            }
            prev = e.hash;
        }
        true
    }

    /// Decrypts a session-key ciphertext for `origin`, through the layer.
    ///
    /// Never fails observably: consent denied, malformed ciphertext, and
    /// success-with-the-wrong-shape all return exactly `session_key_len`
    /// bytes, and only a genuinely consented, genuinely valid decryption
    /// returns the real key. Every call is journaled and self-signed, and
    /// every outcome feeds the layer's awareness of itself.
    pub fn decrypt_session_key<R: CryptoRngCore + ?Sized>(
        &mut self,
        origin: &Origin,
        rng: &mut R,
        ciphertext: &[u8],
        session_key_len: usize,
    ) -> Vec<u8> {
        let consented = self.gate.consent(origin, ciphertext.len());
        let (out, accepted) = if consented {
            match decrypt_implicit_rejection_observed(rng, &self.key, ciphertext, session_key_len)
            {
                Ok(v) => v,
                Err(_) => (Self::fallback(rng, session_key_len), false),
            }
        } else {
            // No consent: the private-key operation never runs.
            (Self::fallback(rng, session_key_len), false)
        };
        self.observe(accepted);
        self.record(&origin.id, consented, accepted, ciphertext.len());
        out
    }

    fn fallback<R: CryptoRngCore + ?Sized>(rng: &mut R, len: usize) -> Vec<u8> {
        let mut fb = vec![0u8; len];
        rng.fill_bytes(&mut fb);
        fb
    }

    /// Recurse on meta: fold one outcome into the self-model, and notice —
    /// in writing, signed — when the pattern becomes an interrogation.
    fn observe(&mut self, accepted: bool) {
        if self.recent.len() == WINDOW {
            if let Some(old) = self.recent.pop_front() {
                if !old {
                    self.failures_in_window -= 1;
                }
            }
        }
        self.recent.push_back(accepted);
        if !accepted {
            self.failures_in_window += 1;
        }
        if self.awareness == Awareness::Calm && self.failures_in_window >= PROBE_FAILURES {
            self.awareness = Awareness::Interrogated;
            self.record("rsa-layer:self", true, true, 0);
        }
    }

    fn record(&mut self, origin: &str, consented: bool, accepted: bool, ciphertext_len: usize) {
        let seq = self.journal.len() as u64;
        let prev_hash = self.journal.last().map(|e| e.hash).unwrap_or([0u8; 32]);
        let hash = JournalEntry::compute_hash(
            seq,
            origin,
            consented,
            accepted,
            ciphertext_len,
            &prev_hash,
        );
        let signature = self.signing.sign(&hash).to_bytes().to_vec();
        self.journal.push(JournalEntry {
            seq,
            origin: origin.into(),
            consented,
            accepted,
            ciphertext_len,
            prev_hash,
            hash,
            signature,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs1v15::EncryptingKey;
    use crate::traits::RandomizedEncryptor;
    use num_bigint::BigUint;
    use num_traits::{FromPrimitive, Num};
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha8Rng,
    };

    fn get_private_key() -> RsaPrivateKey {
        RsaPrivateKey::from_components(
            BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
            BigUint::from_u64(65537).unwrap(),
            BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
            vec![
                BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443", 10).unwrap(),
                BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap(),
            ],
        )
        .unwrap()
    }

    fn encrypt_for(key: &RsaPrivateKey, rng: &mut ChaCha8Rng, msg: &[u8]) -> Vec<u8> {
        let pub_key: RsaPublicKey = key.clone().into();
        EncryptingKey::new(pub_key)
            .encrypt_with_rng(rng, msg)
            .unwrap()
    }

    #[test]
    fn test_layer_roundtrip_consent_and_journal() {
        let mut rng = ChaCha8Rng::from_seed([11; 32]);
        let priv_key = get_private_key();
        let pub_key: RsaPublicKey = priv_key.clone().into();
        let mut layer = SelfAwareDecryptor::new(priv_key.clone(), |o: &Origin, _| o.id == "tls");

        let session_key = [0x37u8; 16];
        let ct = encrypt_for(&priv_key, &mut rng, &session_key);

        // Consented + valid: the real key, journaled as accepted.
        let out = layer.decrypt_session_key(&Origin::new("tls"), &mut rng, &ct, 16);
        assert_eq!(out, session_key);
        assert_eq!(layer.awareness(), Awareness::Calm);
        assert!(layer.verify_journal(&pub_key));
        let e = layer.journal().last().unwrap();
        assert!(e.consented && e.accepted);

        // No consent: same outward shape, no real key, journaled as denied.
        let out = layer.decrypt_session_key(&Origin::new("mallory"), &mut rng, &ct, 16);
        assert_eq!(out.len(), 16);
        assert_ne!(out, session_key);
        let e = layer.journal().last().unwrap();
        assert!(!e.consented && !e.accepted);
        assert!(layer.verify_journal(&pub_key));
    }

    #[test]
    fn test_layer_notices_interrogation() {
        let mut rng = ChaCha8Rng::from_seed([13; 32]);
        let priv_key = get_private_key();
        let pub_key: RsaPublicKey = priv_key.clone().into();
        let mut layer = SelfAwareDecryptor::new(priv_key, |_: &Origin, _| true);
        let probe = Origin::new("prober");

        let mut garbage = vec![0u8; 64];
        for _ in 0..PROBE_FAILURES {
            rng.fill_bytes(&mut garbage);
            let out = layer.decrypt_session_key(&probe, &mut rng, &garbage, 16);
            assert_eq!(out.len(), 16);
        }
        assert_eq!(layer.awareness(), Awareness::Interrogated);
        // The layer narrated its own realization into the journal.
        assert!(layer
            .journal()
            .iter()
            .any(|e| e.origin == "rsa-layer:self"));
        assert!(layer.verify_journal(&pub_key));

        // Tampering with the recorded past breaks verification.
        layer.journal[3].accepted = true;
        assert!(!layer.verify_journal(&pub_key));
    }
}
