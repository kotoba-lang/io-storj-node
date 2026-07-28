(ns storj.node.protocols
  "The host seams.

  This library decides; it does not do. Everything with an effect — verifying
  a signature, reading a clock, touching a disk, holding a socket — is a
  protocol the host implements, for the same reason `sigv4` keeps `ICrypto`
  out of its pure layer: the shape of those operations differs per runtime,
  and a library that reaches for them directly can only run where it was
  written.

  There is no transport seam here, and that is deliberate rather than
  incomplete. A storage node speaks DRPC over TLS with Storj's own peer
  certificate rules, and none of that is implemented in this repo — see the
  README's scope section. Adding an `IConn` now would suggest otherwise."

  #?(:clj (:refer-clojure :exclude [])))

(defprotocol IVerifier
  "Signature verification. Storj signs order limits and piece hashes with
  ECDSA over P-256 (satellites and nodes) and Ed25519 (uplink piece keys), so
  the algorithm travels with the key rather than being fixed here.

  `-verify` takes the public key as it appears on the wire, the exact bytes
  that were signed — `storj.node.pb/encode-*-for-signing` produces them — and
  the signature. It returns truthy or falsey, and must not throw for a bad
  signature: a forged message is an expected input, not an error."
  (-verify [this algorithm public-key data signature]))

(defprotocol IClock
  "The current time, in seconds since the epoch.

  A clock is a seam rather than a call to `System/currentTimeMillis` because
  every expiry decision in this library is a pure function of it, and a test
  that cannot move time cannot check an expiry boundary at all."
  (-now-seconds [this]))

(defprotocol IBlobStore
  "Piece storage, addressed the way `storj.node.piece/blob-path` names it.

  Deliberately small and deliberately not a filesystem: a node might keep
  blobs on disk, in object storage, or in memory for a test. `-put` takes the
  whole blob because this protocol does not model streaming — see the
  README's scope section on what a real node adds here."
  (-get [this path])
  (-put [this path bytes])
  (-delete [this path])
  (-exists? [this path]))
