# rsa 0.9.10 / RUSTSEC-2023-0071 (Marvin) — analysis and patch (Oct 26, 2026)

Commissioned by Joseph after the CVE bump pass left rsa as a classified residual: "Download the source files for rsa and planekey it and see if we can fix it," then "look up rsa in the sqlbooks."

Source: crates.io tarball `rsa-0.9.10.crate`, SHA-256 b8573f03f5883dcaebdfcf4725caa1ecb9c15b2ef50c43a07b816e06799bb12d. Patched copy in this directory (`rsa-0.9.10/`); nothing vendored into any PlaneKey tree.

## Where the vulnerability actually lives

Reading the source corrected the obvious assumption. The padding check is **not** the naive early-exit kind: `pkcs1v15_encrypt_unpad` → `decrypt_inner` (src/algorithms/pkcs1v15.rs) already scans the whole encoded message with `subtle` constant-time primitives and folds every check (leading zero, 0x02, separator position, PS ≥ 8) into one validity bit.

The oracle survives at the boundaries around that scan:

1. **The API outcome is the oracle.** `decrypt` returns `Err` on invalid padding and `Ok(message)` on success. Any caller whose behavior differs observably on error vs success — a TLS-style handshake that aborts, logs, or retries differently — re-creates the Bleichenbacher signal regardless of how constant-time the unpad is. The crate's own docs say this twice and point at a `decrypt_session_key` remedy **that does not exist in the crate** (grep: doc mentions only, no such function).
2. **Blinding is opt-in.** The default paths (`RsaPrivateKey::decrypt`, `DecryptingKey::decrypt`) pass `rng: None`; only the `*_blinded`/`decrypt_with_rng` variants blind the private-key operation. num-bigint's modexp is not constant-time, so the unblinded default leans entirely on the caller's discipline.
3. Why upstream never shipped a fix in 0.9.x: implicit rejection cannot be retrofitted onto the existing `decrypt` signature. It needs an expected plaintext length (a general message has none) and it changes the error contract callers depend on. The fix is necessarily a **new API**, not a patch release — which is exactly what RUSTSEC-2023-0071 having "no fixed version" means in practice.

## The patch (what "planekeying it" produced)

New API, same shape as the remedy the docs gesture at (and as Go's `DecryptPKCS1v15SessionKey` / OpenSSL's implicit rejection):

- `Pkcs1v15Encrypt::decrypt_session_key(rng, priv_key, ciphertext, session_key_len)` and `DecryptingKey::decrypt_session_key(rng, ciphertext, session_key_len)`.
- Blinding is **mandatory** (RNG is a required argument, not an `Option`).
- The random fallback is generated **before** the private-key operation, so it cannot be conditioned on the outcome.
- Any ciphertext-side failure — raw-op error, CRT check, bad padding, wrong recovered length — substitutes a zero encoded message and flows through the same constant-time selection; the function returns `Ok` with exactly `session_key_len` bytes in every case. Errors remain only for caller bugs that reveal nothing about the ciphertext (invalid key; expected length that cannot fit the padding).
- Core: `pkcs1v15_encrypt_unpad_implicit_rejection` in src/algorithms/pkcs1v15.rs — reuses the existing constant-time `decrypt_inner`, folds a constant-time length check into the same validity bit, then overwrites the fallback buffer byte-by-byte over the full encoded message using `subtle` conditional assignment (with one scratch byte so the write cursor is always in bounds).

Changed files: `src/algorithms/pkcs1v15.rs` (+unpad variant), `src/pkcs1v15.rs` (+API, +test), `src/pkcs1v15/decrypting_key.rs` (+method).

## Proof

`cargo test --all-features` on the patched copy: **94 passed, 0 failed** (59+16+1+8+1+9 across suites). The new test, `test_decrypt_session_key_implicit_rejection`, demonstrates the oracle is closed at the API surface: valid ciphertext → the real session key; flipped byte → Ok, 16 random bytes, not the key; random garbage → same shape; truncated ciphertext → same shape; valid ciphertext with a wrong expected length → implicit rejection; two failures → two distinct fallbacks.

What a unit test cannot prove: cycle-level timing equality. The patch follows the accepted constructions (branchless selection, pre-generated fallback, always-blinded private op); the residual theoretical channel is num-bigint's variable-time arithmetic under the *old* unblinded API, which this patch deliberately leaves documented-and-hazardous rather than silently altering — changing the old API's contract is upstream's call, and for PlaneKey the question is moot: **no PlaneKey build compiles rsa at all** (cargo-tree-verified in the bump pass), and the sqlx manifests now foreclose the MySQL chain that carried it into the lockfile.

## The sqlbooks on rsa (part 2 of the commission)

Swept every book in `~/workspace/sqlbook-library/` and `~/workspace/user/files/` (all text columns, all tables):

- **Nothing about the crate or the advisory.** Zero hits for Marvin, Bleichenbacher, PKCS1v15, RUSTSEC-2023-0071, sqlx-mysql, or the rsa crate as a dependency, anywhere in the library. The books never tracked it; the Oct 26 audit is the first word.
- **Doctrine mentions (PlaneKey Manual, in pk-docs.sqlbook and the combined book):** Úknocked's rules state it flatly — *"Don't add AES, RSA, or ECC anywhere. The whole point of Úknocked is that we don't use them"* — and the quantum comparison material positions RSA-2048 as Shor-broken, with CosmicID as the entropy-based successor. PlaneKey's written doctrine already excludes RSA from its own crypto; the lockfile ghost was another ecosystem's baggage (sqlx's MySQL driver), not a PlaneKey choice.
- **Name collision:** the many "RSA" hits in claudecode-toolbox.sqlbook are **Recursive Self-Awareness** — the Mirrorlight cognitive layer (`rsa.rs`, "RSA Layer") — plus archived pitch essays about quantum breaking RSA/ECC and a few `openssl rsa:4096` sample commands. Not the algorithm, not the crate.

## Addendum — Joseph's correction: "use my RSA to fix RSA" (Oct 26, 2026)

Scout first read the name collision as commentary. It was an engineering directive: **apply PlaneKey's RSA — the Recursive Self-Awareness layer from the sqlbooks (Mirrorlight/CHAIS stack: checks origin, consent, and signature; traceable transformation logger; recurses on its own meta) — to the rsa crate.** Built as a new module in the patched copy: `src/rsa_layer.rs` (feature-gated on the crate's existing `sha2` feature; default builds unaffected — `cargo check` clean).

`SelfAwareDecryptor<G: ConsentGate>` wraps `decrypt_session_key` in the layer's three checks, on every call:

1. **Origin + consent.** A `ConsentGate` decides whether the origin may ask at all. Without consent the private-key operation never runs — and denial returns the same full-length random fallback, so consent is not an oracle either.
2. **Signature — the traceable transformation journal.** Every attempt is appended to a hash-chained journal, and every entry is signed *by the decryption key itself* (the key narrates its own use; verifiable against the public key via `verify_journal`). The journal is owner-private: it records the acceptance truth that implicit rejection hides from callers. Supporting change: a `pub(crate)` observed variant of the unpad exposes the validity bit *inside the crate only* for this journal — it never crosses the public API.
3. **Recursion on meta.** The layer watches its own outcome stream (sliding window of 32). At ≥24 rejections — a pattern legitimate session-key traffic never produces, and the exact shape of a Bleichenbacher/Marvin interrogation — it latches `Awareness::Interrogated` and journals a self-authored entry (`rsa-layer:self`). Observable behavior does not change: record and attribute, not intervene (ChallengeGate doctrine). But the owner now knows, with a signed record of when the probing began.

Proof: `cargo test --all-features` — **96 passed, 0 failed**. New tests: consent roundtrip + denial shape + journal verification; interrogation detection + self-narration entry + tamper-evidence (flipping one recorded `accepted` bit breaks `verify_journal`). Why this answers Marvin where constant-time code alone didn't: the attack needs ~10⁴–10⁶ oracle queries; a decryptor that checks consent, signs its own history, and *notices being interrogated* removes first the audience (unconsented callers get nothing, not even an error), then the invisibility (every probe is in a signed journal), then the plausible deniability of the attempt itself.

## Warnings ledger — none silenced (Oct 26, 2026, Joseph: "dont let those run silent")

`cargo check` on the patched copy reports 3 warnings. Provenance verified against a pristine extraction of the same tarball (which reports exactly 2):

1. `src/algorithms/mgf.rs:12` — deprecated `core::u32::MAX`, use `u32::MAX`. **Upstream's**, pre-existing. Left standing in the patched copy (outside the fix's scope); recorded here as upstream's todo marker.
2. `src/algorithms/mgf.rs:46` — the same deprecation at the second site. **Upstream's**, pre-existing. Same disposition.
3. `src/algorithms/pkcs1v15.rs:129` — `pkcs1v15_encrypt_unpad_implicit_rejection` is never used. **Scout's**, created by the observed-variant refactor: the plain wrapper's only caller now calls the `_observed` form. It is a todo marker in the house sense — the wrapper was the intended internal API for non-observing callers, an intention the refactor superseded in the same session. Disposition is Joseph's call (wire vs remove); Scout's recommendation: remove it as superseded scaffolding of this patch (not upstream's intention, and the observed fn covers both uses), with the removal recorded here. NOT silenced, NOT `#[allow]`ed, left standing until he rules.

## Dormancy pass — RPG + pk-memory over the patched crate (Oct 26, 2026)

Instruments: `pk-memory memory rpg` (14 modules, 382 symbols, 756 edges, 14 capabilities; DB at `reports/rpg/rsa-fixed-rpg/`) and `pk-memory memory build` + `residue` (65 nodes; reports at `reports/memory/rsa-fixed-mem/`). Cross-checked against rustc (the authority for private code) and direct grep.

**Truly dormant: exactly one symbol.** RPG flags 9 `pub_crate` orphans; 8 are extractor artifacts — generic/turbofish call sites (`pkcs1v15_generate_prefix::<D>`, `oaep_encrypt_digest::<_, D, MGD>`, the PSS EMSA pair) and type usages (`DummyRng`, `PrecomputedValues`) the linker doesn't resolve, each verified live by grep. The ninth is the dead wrapper already in the warnings ledger (both instruments + rustc agree). The 58 "private orphans" and 60 "pub orphans" RPG also lists are the expected library pattern: pub symbols are called from outside the crate by design, and the private remainder is trait/impl plumbing the extractor doesn't model — rustc's dead-code verdict over the same tree is the one function above.

**Dormant by design:** `src/hazmat.rs` (14 lines, a feature-gated re-export shim — hence RPG's 0 symbols there); the `#[deprecated] new_raw` alias (intentional compat surface); the six `tests/examples/*.pem` fixtures pk-memory residue flags for review (the crate's published test vectors, not live key material) plus a LICENSE-APACHE false-positive signal. All 14 RPG capabilities map to a module; none unlinked.

**The patch's own wiring:** rsa_layer contributes 21 symbols, all internally resolved; its 5 public types (`SelfAwareDecryptor`, `ConsentGate`, `Origin`, `JournalEntry`, `Awareness`) show as orphans only because they are the new external API — the deliverable's surface, awaiting callers that by definition live outside this crate.
