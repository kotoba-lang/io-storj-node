# io-storj-node

`storj.node.*` — the **storage node** side of Storj, as portable `.cljc`:
identities, order limits, the bytes their signatures cover, and how a piece is
laid out on disk.

Companion to [`io-storj`](https://github.com/kotoba-lang/io-storj), which is
the client side and reaches Storj through the S3 gateway. This repo is the
other end of the network: not a program that talks to Storj, but the part of
Storj a node is.

| Namespace | What it owns |
|---|---|
| `storj.node.id` | Node IDs — base58check, the version byte, difficulty. |
| `storj.node.identity` | What a peer's certificate chain says, and whether to believe it. |
| `storj.node.der` | Just enough DER to read an X.509 certificate, and to write one. |
| `storj.node.certificate` | The two certificates a Storj identity is made of. |
| `storj.node.mint` | The proof of work, and the identity it names. |
| `storj.node.pb` | The Storj messages, and **the exact bytes their signatures cover**. |
| `storj.node.orders` | Whether an order limit may be acted on, and every reason it may not. |
| `storj.node.piece` | Blob paths and the V1 piece header. |
| `storj.node.protocols` | The host seams: `IVerifier`, `IClock`, `IBlobStore`. |
| `storj.node.host.verify` | The reference `IVerifier` — the four schemes Storj presents. |
| `storj.node.host.keys` | The reference `IKeyMaterial` — key generation, signing, entropy. |
| `storj.node.bytes` | The one file that knows which runtime it is on. |

## Scope — read this before using it

**This is the protocol core of a storage node, not a storage node.** What is
here decides; what is missing does.

Implemented and tested on two runtimes:

- Node ID encoding, decoding, version handling and difficulty.
- Decoding `OrderLimit`, `Order`, `PieceHash`, `PieceHeader`, and reproducing
  the bytes Storj signs for each.
- Admission of an order limit: addressed to this node, unexpired, action
  matches, signature valid — with the crypto deliberately last.
- Blob path derivation and the 512-byte V1 piece header.
- Reading a peer's certificate chain, deriving its node id from the CA key,
  and admitting or refusing it — chain signatures, difficulty floor, expected
  id, identity version, extension rules.
- **Minting an identity**: the proof of work over CA keys, and the CA and
  leaf certificates that carry it — accepted by `storj.io/common` and
  byte-identical to what `identity.NewCA` produces for the same inputs.
- Signature verification for all four schemes Storj presents: ECDSA-SHA256,
  ed25519 piece keys, and RSA under **both** PKCS#1 v1.5 (certificates) and
  PSS (messages) — checked against signatures Storj's own code produced, on
  both runtimes.

**Not implemented.** A node built on this would still need all of it:

- **The TLS handshake and the socket.** The peer certificate *rules* are
  implemented (`storj.node.identity`), the signature check underneath them is
  implemented (`storj.node.host.verify`), and DRPC framing lives in
  [`kotoba-lang/drpc`](https://github.com/kotoba-lang/drpc) — but nothing here
  terminates TLS or opens a connection. What is left there is mechanism: the
  decisions a peer certificate forces are made above.
- **Persisting an identity.** `mint` returns keys; writing them to disk means
  choosing a format, a location and a permission mode, which is the host's to
  choose.
- **Order settlement** (`SettlementWithWindow`), check-in, retain/garbage
  collection bloom filters, graceful exit.
- **Streaming.** `IBlobStore` moves whole blobs; a real node streams and
  enforces the limit as it goes.
- **The uplink side entirely** — erasure coding, encryption, segment
  metadata. That asymmetry is not an oversight: a node stores opaque shares
  and never decodes anything, which is exactly why the node side fits in a
  library like this and the client side does not.

No live request has ever been made against a satellite from this code.

## Verification

The parts of this protocol that matter cannot be checked against themselves.
Whether `encode-order-limit-for-signing` produces the bytes a satellite
actually signed is a question about gogoproto's treatment of `nullable=false`
fields and Go's definition of a zero time — and reasoning about it from the
`.proto` is precisely how one writes a plausible implementation that verifies
nothing.

So the expected values come from elsewhere:

- **Storj's own code.** `testdata/gen_vectors.go` links `storj.io/common` and
  asks `signing.EncodeOrderLimit`, `EncodeOrder`, `EncodePieceHash`,
  `NodeID.String()` and `PieceID.String()` what they emit. Those outputs are
  the literals in the tests.
- **Published identities.** The four satellite node IDs Storj publishes are
  decoded in full: length, version byte, double-SHA-256 checksum, difficulty.
- **A real generated identity.** `testdata/gen_identity.go` runs the same
  `identity.NewCA` a node operator does, and the resulting certificates are
  checked in. CI runs that program with `-verify`, which re-parses the fixture
  with `storj.io/common` and asserts the node id, version and chain
  relationships the tests claim — holding the fixture to the reference
  implementation rather than to a previous run of the generator.
- **The other direction.** Every other vector has the reference
  implementation produce bytes and this library assert it reads them the same
  way. `testdata/verify_minted.go` inverts it: this library mints a chain and
  `storj.io/common` is asked whether it is a Storj identity — parsed, both
  signatures checked, `peertls.VerifyPeerCertChains`, `NodeIDFromCert`,
  `PeerIdentityFromChain`, and the structural details down to which
  certificate carries a subjectKeyIdentifier. A parser agreeing with its own
  writer proves nothing, and reading a certificate correctly is not evidence
  that one can be written. CI mints afresh on both runtimes every run.
- **Byte-identical reconstruction.** Stronger still, and deterministic: given
  the serial, key and extensions of the fixture's real certificate,
  `storj.node.certificate` rebuilds its signed body and the result is equal,
  byte for byte, to what Go's `x509.CreateCertificate` emitted — 282 bytes
  for the CA and 268 for the leaf. A certificate that merely parses leaves
  room for a field encoded a legal-but-different way; equality does not.
- **Real signatures.** `testdata/gen_sigs.go` signs with `pkcrypto` and
  `storj.PiecePrivateKey` and records the result; CI runs it with `-verify`.
  Until this existed, `IVerifier` was stubbed everywhere and the entire
  admission path — certificate chains and order limits both — had never once
  seen a signature that could fail.
- **Both runtimes.** JVM and nbb run the same suite. SHA-256 comes from
  `MessageDigest` on one and `@noble/hashes` on the other, and varint
  handling has to survive JavaScript truncating bitwise operators at 32 bits.
  The verifier is the sharpest case: `java.security` on one side, Node's
  OpenSSL bindings on the other, asked the same four questions.

Reading the `.proto` and reasoning carefully produced an implementation that
was wrong in two independent ways, and the vectors caught both:

1. `limit`, `action` and `satellite_signature` were placed at field numbers
   8, 9 and 6. They are 6, 7 and 10.
2. An unset timestamp was assumed to reach the wire as `seconds = 0`. Go's
   zero time is year 1, so it arrives as `-62135596800`, and the signing form
   drops the field on that basis. Every satellite signature would have failed.

A third came from Storj's own encoder disagreeing with a round trip: the last
byte of a node ID is the **identity version**, not part of the hash. It is
zeroed on encode and rewritten on decode, and `Difficulty()` skips it.

A fourth would have been just as quiet: an OID whose first byte is 80 or
above encodes a first arc of 2, and dividing by 40 instead — the obvious
reading — turns Storj's `2.999.2.1` identity-version extension into
`24.39.2.1`, so every certificate would silently look unversioned.

A fifth is the one this repo went looking for rather than tripped over.
Storj signs *messages* with RSA-PSS and *certificates* with PKCS#1 v1.5 —
same key, same hash, two paddings. One RSA implementation used for both
questions does not raise an error; it reports a valid signature as invalid,
and only on the identities old enough to still use RSA. The fixture records
both signatures over the same message so each padding is checked against the
other's bytes.

Writing certificates added two more, both caught in the first hour:

6. **`[3] EXPLICIT Extensions` is two nested constructions**, not one —
   `Extensions` is itself a `SEQUENCE OF`. Emitting the extensions directly
   inside the context tag produces a certificate whose first extension's
   *fields* parse as extensions. The reader caught the writer: the rule that
   refuses duplicate extension IDs fired.
7. **A `loop` accumulator seeded from a rebound binding.** `loop` bindings are
   sequential like `let`, so seeding the output vector from `v` after `v` had
   been rebound to `(quot v 128)` collapsed every subidentifier below 128 to
   zero — which turned *every* OID into the same OID. Also caught by the
   duplicate-extension rule, which is the only reason it did not become a
   certificate that parsed and meant something else.

A near miss worth recording too: the first version of the serial-number test
asserted a 16-byte length, and a 128-bit serial encodes as 17 bytes whenever
its top bit is set. It passed about half the time. It was found because a
rerun disagreed with the run before it, not because it failed.

The suite has been checked to fail when each of those is reintroduced,
including deriving the node id from the leaf rather than the CA, dropping the
self-signature check that ends a chain, verifying PSS with PKCS#1 padding,
using a hash-length PSS salt instead of the largest that fits, and handing
ed25519 its raw key without the SPKI wrapper, flattening the extensions
context tag, seeding the OID accumulator from the rebound binding, emitting a
fixed unused-bit count, dropping an INTEGER's sign byte, accepting the first
key regardless of difficulty, signing the leaf with its own key, hashing the
whole SubjectPublicKeyInfo for the subjectKeyIdentifier, and tagging the
validity dates as UTCTime.

Nineteen controls in total. The eleven for the verifier were run on both
runtimes, because that namespace is two implementations of the same four
questions; the eight for minting were run on the JVM, because the code they
break is shared `.cljc` and would fail identically on either.

Two of the nineteen silently failed to compile on the first attempt and
reported nothing at all. A control that produces no failure and a control
that produces no result look the same from a distance, and neither is
evidence — which is worth stating twice, because it happened twice.

## Test

```sh
clojure -M:test                                              # JVM
nbb --classpath "$(clojure -A:cljs -Spath)" scripts/verify-cljs.cljs
clojure -M:lint
cd testdata && go run gen_vectors.go                         # regenerate vectors
cd testdata && go run gen_sigs.go -verify                    # recheck signatures
clojure -M:mint testdata/minted.edn 16                       # mint an identity
cd testdata && go run verify_minted.go -in minted.edn        # and let Storj judge it
```

`testdata/` is a vector generator, not a dependency: nothing under `src/`
links Go, and the library's own dependencies are two `.cljc` libraries
(`proto` for the wire codec, `io-multiformats` for base58/base32/SHA-256).
