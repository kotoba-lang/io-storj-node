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

**Not implemented.** A node built on this would still need all of it:

- **DRPC over TLS**, with Storj's peer certificate rules and node ID
  verification against the presented chain. This is the largest missing
  piece and the reason nothing here can yet talk to a satellite.
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

The suite has been checked to fail when each of those is reintroduced.

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
