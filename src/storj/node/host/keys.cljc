(ns storj.node.host.keys
  "The reference `IKeyMaterial` — key generation, signing and entropy.

  The counterpart to `storj.node.host.verify`, and under `host` for the same
  reason: nothing here decides anything. It generates P-256 key pairs because
  `pkcrypto.GeneratePrivateKey` does, signs with ECDSA over SHA-256 producing
  the ASN.1 form `ecdsa.SignASN1` produces, and takes randomness from the
  platform's cryptographic source rather than from a seeded generator.

  A caller holding keys somewhere this cannot reach — an HSM, a remote
  signer, a file on a node that is already running — implements
  `IKeyMaterial` and never loads this namespace."
  (:require [storj.node.bytes :as b]
            [storj.node.protocols :as p]
            #?(:cljs ["node:crypto" :as crypto]))
  #?(:clj (:import (java.security KeyPairGenerator SecureRandom Signature)
                   (java.security.spec ECGenParameterSpec))))

(def curve
  "P-256, which `pkcrypto.GeneratePrivateKey` returns and every current Storj
  identity uses."
  #?(:clj "secp256r1" :cljs "prime256v1"))

#?(:clj (def ^:private secure-random (SecureRandom.)))

(defn generate-keypair
  "A fresh P-256 key pair. The public half comes back as DER SPKI, because
  that is what a certificate carries and what a node id is derived from."
  []
  #?(:clj
     (let [g (doto (KeyPairGenerator/getInstance "EC")
               (.initialize (ECGenParameterSpec. curve) secure-random))
           kp (.generateKeyPair g)]
       {:private (.getPrivate kp)
        :public-spki (b/->ints (.getEncoded (.getPublic kp)))})
     :cljs
     (let [kp (.generateKeyPairSync crypto "ec"
                                    #js {:namedCurve curve
                                         :publicKeyEncoding #js {:type "spki" :format "der"}})]
       {:private (.-privateKey kp)
        :public-spki (b/->ints (.-publicKey kp))})))

(defn sign
  "An ECDSA-SHA256 signature in the ASN.1 form Storj expects.

  Node's default `dsaEncoding` is already `der`; it is named anyway, because
  the alternative — the fixed-width `ieee-p1363` pair — is the same length as
  a plausible DER signature and would be rejected by every verifier without
  ever looking malformed."
  [algorithm private-key data]
  (when-not (= :ecdsa-sha256 algorithm)
    (throw (ex-info "storj.node.host.keys: only ecdsa-sha256 signing is implemented"
                    {:algorithm algorithm})))
  #?(:clj
     (let [s (doto (Signature/getInstance "SHA256withECDSA")
               (.initSign private-key secure-random)
               (.update (b/->native (vec data))))]
       (b/->ints (.sign s)))
     :cljs
     (b/->ints (.sign crypto "sha256" (b/->native (vec data))
                      #js {:key private-key :dsaEncoding "der"}))))

(defn random-bytes [n]
  #?(:clj  (let [a (byte-array n)] (.nextBytes secure-random a) (b/->ints a))
     :cljs (b/->ints (.randomBytes crypto n))))

(def key-material
  "An `IKeyMaterial` backed by this runtime's own crypto."
  (reify p/IKeyMaterial
    (-generate-keypair [_] (generate-keypair))
    (-sign [_ private-key algorithm data] (sign algorithm private-key data))
    (-random-bytes [_ n] (random-bytes n))))
