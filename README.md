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
| `storj.node.der` | Just enough DER to read an X.509 certificate. |
| `storj.node.pb` | The Storj messages, and **the exact bytes their signatures cover**. |
| `storj.node.orders` | Whether an order limit may be acted on, and every reason it may not. |
| `storj.node.piece` | Blob paths and the V1 piece header. |
| `storj.node.protocols` | The host seams: `IVerifier`, `IClock`, `IBlobStore`. |
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

**Not implemented.** A node built on this would still need all of it:

- **The TLS handshake and the socket.** The peer certificate *rules* are
  implemented (`storj.node.identity`) and DRPC framing lives in
  [`kotoba-lang/drpc`](https://github.com/kotoba-lang/drpc), but nothing here
  terminates TLS or opens a connection.
- **Identity generation** — the proof of work that mints an ID, and the CA
  and leaf certificates that carry it.
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
- **Both runtimes.** JVM and nbb run the same suite. SHA-256 comes from
  `MessageDigest` on one and `@noble/hashes` on the other, and varint
  handling has to survive JavaScript truncating bitwise operators at 32 bits.

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

The suite has been checked to fail when each of those is reintroduced,
including deriving the node id from the leaf rather than the CA, and dropping
the self-signature check that ends a chain.

## Test

```sh
clojure -M:test                                              # JVM
nbb --classpath "$(clojure -A:cljs -Spath)" scripts/verify-cljs.cljs
clojure -M:lint
cd testdata && go run gen_vectors.go                         # regenerate vectors
```

`testdata/` is a vector generator, not a dependency: nothing under `src/`
links Go, and the library's own dependencies are two `.cljc` libraries
(`proto` for the wire codec, `io-multiformats` for base58/base32/SHA-256).
