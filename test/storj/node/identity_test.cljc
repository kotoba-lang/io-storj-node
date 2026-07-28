(ns storj.node.identity-test
  "Certificate reading and chain admission, against a real Storj identity.

  The certificates below were produced by `testdata/gen_identity.go`, which
  calls `identity.NewCA` and `ca.NewIdentity` — the same code a node operator
  runs. They are checked in rather than regenerated, because generation is
  random; CI instead runs that program with `-verify`, which parses these same
  bytes with `storj.io/common` and asserts the node id, version and chain
  relationships this file claims. Holding the fixture to the reference
  implementation is a better check than holding it to a previous run of the
  generator.

  The node id in particular is not this library's own arithmetic: it was also
  reproduced independently with `openssl`/`shasum` before any of this code
  existed."
  (:require [clojure.test :refer [deftest is testing]]
            [storj.node.bytes :as b]
            [storj.node.der :as der]
            [storj.node.id :as node-id]
            [storj.node.identity :as ident]
            [storj.node.protocols :as p]))

(defn- unhex [s]
  (mapv #?(:clj  #(Integer/parseInt % 16)
           :cljs #(js/parseInt % 16))
        (re-seq #"[0-9a-fA-F]{2}" s)))

;; ── fixture — testdata/identity.edn, do not hand-edit ───────────────────────

(def ca-der
  (unhex (str "3082016f30820116a003020102021100e0e85972cb9f4bc4a9c7fd2de3d2e105300a06"
              "082a8648ce3d0403023010310e300c060355040a130553746f726a3022180f30303031"
              "303130313030303030305a180f30303031303130313030303030305a3010310e300c06"
              "0355040a130553746f726a3059301306072a8648ce3d020106082a8648ce3d03010703"
              "420004d60d807db7ab8ab86984a68a811eba82dd555926be3c0d1f4aadaf99a3616f95"
              "1b836a071a7fea4d78c073a6ac7d9a6f6741c4b9ac23e6dd740ec03042b693d4a34d30"
              "4b300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff30"
              "1d0603551d0e041604143c232d6941c0f96c2aa70642bda4f02df45d18ff3009060488"
              "370201040100300a06082a8648ce3d040302034700304402202b4a233154f4fba7a35a"
              "79c343cc250e7f2969dd6dfc558b9e0cf9fa075512b2022051c0b57d21d7fbc99af56d"
              "c81df182615274e4e136373e3cabf73e6bb94cb589")))

(def leaf-der
  (unhex (str "3082016130820108a003020102021100ec18bc171a10ac2a4eacb352abbaf085300a06"
              "082a8648ce3d0403023010310e300c060355040a130553746f726a3022180f30303031"
              "303130313030303030305a180f30303031303130313030303030305a3010310e300c06"
              "0355040a130553746f726a3059301306072a8648ce3d020106082a8648ce3d03010703"
              "4200048a56ec7b312a058f860dfac078088f8ecba5869502954a57ecee568c7d1de5dc"
              "de91f0d6866c02c150b9bcabf01f9c9386bc58eff11c5503c63e8527c4c5ac52a33f30"
              "3d300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b06010505"
              "07030106082b06010505070302300c0603551d130101ff04023000300a06082a8648ce"
              "3d0403020347003044022066d8d15e2a40d35b16126bea4a99f31bc69c92723d29eb38"
              "0cc95798bbb14b0302205622d4ed1ebf9119894d7b9fc8a67519361ec558a0db106aaf"
              "af999169a55159")))

(def ca-spki-der
  (unhex (str "3059301306072a8648ce3d020106082a8648ce3d03010703420004d60d807db7ab8ab8"
              "6984a68a811eba82dd555926be3c0d1f4aadaf99a3616f951b836a071a7fea4d78c073"
              "a6ac7d9a6f6741c4b9ac23e6dd740ec03042b693d4")))

(def node-id-hex "92a64c34cd5ba09161c96a0ee1200b34881b7d0378587946978ee11f59440c00")
(def node-id-b58 "127ay6iM21ux5yyKqysaUAPCK8VnUY2KsHgRnuAZpmVLJem4pV7")
(def expected-difficulty 10)

;; ── DER ─────────────────────────────────────────────────────────────────────

(deftest reads-the-certificate-structure
  (let [cert (der/parse ca-der)]
    (is (der/tag? cert :sequence))
    (is (= 3 (count (der/children cert)))
        "tbsCertificate, signatureAlgorithm, signatureValue")))

(deftest oid-arcs-above-eighty
  ;; 2.999.2.1 encodes its first two arcs as the single byte pair 88 37. The
  ;; obvious rule — divide by 40 — turns that into 24.39 and every Storj
  ;; extension becomes unrecognisable.
  (let [el (der/parse (unhex "060488370201"))]
    (is (= "2.999.2.1" (der/oid el))))
  (testing "and the ordinary branch still works"
    (is (= "2.5.29.15" (der/oid (der/parse (unhex "0603551d0f")))))
    (is (= "1.2.840.10045.4.3.2"
           (der/oid (der/parse (unhex "06082a8648ce3d040302")))))))

(deftest der-refuses-what-it-cannot-represent
  (testing "trailing bytes after the certificate"
    (is (thrown? #?(:clj Exception :cljs js/Error) (der/parse (conj ca-der 0x00)))))
  (testing "indefinite length is not DER"
    (is (thrown? #?(:clj Exception :cljs js/Error) (der/parse [0x30 0x80 0x00 0x00]))))
  (testing "a length that runs past the input"
    (is (thrown? #?(:clj Exception :cljs js/Error) (der/parse [0x30 0x7f 0x01]))))
  (testing "a bit string claiming unused bits"
    (is (thrown? #?(:clj Exception :cljs js/Error)
                 (der/bit-string-bytes (der/parse [0x03 0x02 0x04 0xff]))))))

;; ── the certificate's fields ────────────────────────────────────────────────

(deftest certificate-fields
  (let [ca (ident/certificate ca-der)]
    (is (= ca-spki-der (:spki-der ca))
        "the public key, as Go's MarshalPKIXPublicKey produced it")
    (is (= :ecdsa-sha256 (:algorithm ca)))
    (is (= 0x30 (first (:tbs-der ca))) "tbs includes its own tag and length")
    (is (= 0x30 (first (:signature ca))) "an ECDSA signature is a DER SEQUENCE")
    (testing "extensions, by OID"
      (is (= #{"2.5.29.15" "2.5.29.19" "2.5.29.14" "2.999.2.1"}
             (set (keys (:extensions ca)))))
      (is (= [0x00] (get (:extensions ca) ident/identity-version-ext))))))

(deftest the-leaf-is-a-different-key
  (is (not= (:spki-der (ident/certificate ca-der))
            (:spki-der (ident/certificate leaf-der)))
      "which is why the node id must come from the CA"))

;; ── the node id ─────────────────────────────────────────────────────────────

(deftest node-id-derives-from-the-ca-key
  (let [ca (ident/certificate ca-der)]
    (is (= node-id-hex (b/hex (ident/node-id ca))))
    (is (= node-id-b58 (node-id/format (ident/node-id ca)))))

  (testing "the version byte is the last byte, not part of the digest"
    (let [ca     (ident/certificate ca-der)
          digest (b/sha256d (:spki-der ca))]
      (is (not= digest (ident/node-id ca)))
      (is (= (subvec digest 0 31) (subvec (ident/node-id ca) 0 31)))
      (is (= 0 (last (ident/node-id ca))))))

  (testing "using the leaf instead yields a different, meaningless id"
    (is (not= (ident/node-id (ident/certificate ca-der))
              (ident/node-id (ident/certificate leaf-der)))))

  (testing "difficulty"
    (is (= expected-difficulty
           (node-id/difficulty (ident/node-id (ident/certificate ca-der)))))))

(deftest version-defaults-to-v0-when-absent
  ;; certificates minted before the extension existed carry no version, and
  ;; IDVersionFromCert treats them as V0 rather than rejecting them
  (is (= 0 (ident/version {:extensions {}})))
  (is (= 0 (ident/version (ident/certificate ca-der))))
  (is (= 7 (ident/version {:extensions {ident/identity-version-ext [7 9]}}))
      "and it is the first raw byte, not an ASN.1 integer"))

;; ── admission ───────────────────────────────────────────────────────────────

(defn- verifier [answer] (reify p/IVerifier (-verify [_ _ _ _ _] answer)))

(def chain [leaf-der ca-der])

(deftest a-real-chain-is-admitted
  (let [r (ident/admit-chain chain {:verifier (verifier true)})]
    (is (:ok? r) (pr-str (:reasons r)))
    (is (= node-id-hex (b/hex (:node-id r))))
    (is (= expected-difficulty (:difficulty r)))))

(deftest the-node-must-be-the-one-dialled
  (let [r (ident/admit-chain chain {:verifier (verifier true)
                                    :expected-node-id (vec (repeat 32 0x11))})]
    (is (not (:ok? r)))
    (is (= #{:node-id-mismatch} (set (map :reason (:reasons r)))))))

(deftest difficulty-floor
  (is (:ok? (ident/admit-chain chain {:verifier (verifier true)
                                      :minimum-difficulty expected-difficulty})))
  (let [r (ident/admit-chain chain {:verifier (verifier true)
                                    :minimum-difficulty 36})]
    (is (not (:ok? r)))
    (is (= #{:insufficient-difficulty} (set (map :reason (:reasons r)))))
    (is (= 36 (:minimum (first (:reasons r)))))))

(deftest a-chain-without-a-ca-names-nobody
  (let [r (ident/admit-chain [leaf-der] {:verifier (verifier true)})]
    (is (not (:ok? r)))
    (is (contains? (set (map :reason (:reasons r))) :chain-too-short))))

(deftest signatures-are-checked-and-checked-last
  (testing "a chain whose signatures do not verify is refused"
    (let [r (ident/admit-chain chain {:verifier (verifier false)})]
      (is (not (:ok? r)))
      (is (= #{:chain-signature-invalid} (set (map :reason (:reasons r)))))))

  (testing "no verifier is a refusal, not a pass"
    (let [r (ident/admit-chain chain {})]
      (is (not (:ok? r)))
      (is (= #{:no-verifier-configured} (set (map :reason (:reasons r)))))))

  (testing "a structurally bad chain costs no asymmetric crypto"
    (let [calls (atom 0)
          v (reify p/IVerifier (-verify [_ _ _ _ _] (swap! calls inc) true))]
      (ident/admit-chain chain {:verifier v :expected-node-id (vec (repeat 32 1))})
      (is (zero? @calls))
      (ident/admit-chain chain {:verifier v})
      (is (= 2 @calls) "leaf against the CA, and the CA against itself"))))

(deftest the-last-certificate-must-sign-itself
  ;; verifyChainSignatures ends with a self-signature check. Without it a chain
  ;; can end in a certificate nobody vouched for — and the node id comes from a
  ;; key in that chain.
  (let [seen (atom [])
        v (reify p/IVerifier
            (-verify [_ _ key data _]
              (swap! seen conj [(b/hex key) (b/hex data)])
              true))]
    (ident/admit-chain chain {:verifier v})
    (let [ca   (ident/certificate ca-der)
          leaf (ident/certificate leaf-der)]
      (is (= [[(b/hex (:spki-der ca)) (b/hex (:tbs-der leaf))]
              [(b/hex (:spki-der ca)) (b/hex (:tbs-der ca))]]
             @seen)
          "the leaf is checked against the CA's key, then the CA against its own"))))

(deftest the-pow-counter-extension-stops-admission
  ;; 2.999.2.2 says the id is derived by hashing a different number of times.
  ;; Nothing in storj/common implements it, so a chain carrying it is either
  ;; from a future this build does not know, or an attempt to be hashed
  ;; differently by different peers. Ignoring it would mean two nodes
  ;; disagreeing about who the presenter is.
  (let [ca (assoc-in (ident/certificate ca-der)
                     [:extensions ident/identity-pow-counter-ext] [3])
        r  (ident/admit-chain [(ident/certificate leaf-der) ca]
                              {:verifier (verifier true)})]
    (is (not (:ok? r)))
    (is (contains? (set (map :reason (:reasons r))) :pow-counter-extension-present))))

(deftest unknown-signature-algorithms-are-refused
  (let [ca (assoc (ident/certificate ca-der) :algorithm [:unknown "1.2.3"])
        r  (ident/admit-chain [(ident/certificate leaf-der) ca]
                              {:verifier (verifier true)})]
    (is (not (:ok? r)))
    (is (contains? (set (map :reason (:reasons r)))
                   :unsupported-signature-algorithm))))

(deftest an-unsupported-identity-version-is-refused
  (let [ca (assoc-in (ident/certificate ca-der)
                     [:extensions ident/identity-version-ext] [9])
        r  (ident/admit-chain [(ident/certificate leaf-der) ca]
                              {:verifier (verifier true)})]
    (is (not (:ok? r)))
    (is (contains? (set (map :reason (:reasons r))) :unsupported-identity-version))))

(deftest duplicate-extensions-are-refused-at-parse-time
  ;; ErrUniqueExtensions. Two extensions with the same id let a reader that
  ;; takes the first and a reader that takes the last disagree about what the
  ;; certificate says — including, for 2.999.2.1, which version it is.
  (let [ext (unhex "3009060488370201040100")
        two (into [] (concat ext ext))
        tbs-tail (into [0xa3 (+ 2 (count two)) 0x30 (count two)] two)]
    (is (thrown? #?(:clj Exception :cljs js/Error)
                 (#'ident/extensions-of
                  (der/children (der/parse (into [0x30 (count tbs-tail)] tbs-tail))))))))
