(ns storj.node.piecestore-test
  "Storing a piece, against a conversation an uplink actually has.

  One message type carries four different things and nothing in the encoding
  says which is which, so a reader driven by anything but real messages
  accepts a limit in the middle of a stream and calls it valid. These come
  from `testdata/gen_piecestore.go`, which builds them with `storj.io/common`
  and signs the order limit the way a satellite does."
  (:require [clojure.test :refer [deftest is testing]]
            [proto.wire :as w]
            [storj.node.host.verify :as v]
            [storj.node.piecestore :as ps]
            [storj.node.protocols :as p]))

(defn- unhex [s]
  (mapv #?(:clj  #(Integer/parseInt % 16)
           :cljs #(js/parseInt % 16))
        (re-seq #"[0-9a-fA-F]{2}" s)))

;; ── testdata/piecestore-vectors.edn, generated — do not hand-edit ───────────

(def satellite-spki
  (unhex (str "3059301306072a8648ce3d020106082a8648ce3d03010703420004d87fe69e302c0963a9"
                        "7403d6c594e84a162bf2c62906900dce3a9f4ef38b3bfc12d238c05dd87d501822b180bd"
                        "31c3fa6a2f4d6f79f5d8b74329879cddec1b95")))

(def storage-node-id
  (unhex "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"))

(def piece-id
  (unhex "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"))

(def upload-first
  (unhex (str "0a8a020a100102030405060708090a0b0c0d0e0f101220101112131415161718191a1b1c"
                      "1d1e1f202122232425262728292a2b2c2d2e2f2220404142434445464748494a4b4c4d4e"
                      "4f505152535455565758595a5b5c5d5e5f2a20707172737475767778797a7b7c7d7e7f80"
                      "8182838485868788898a8b8c8d8e8f30403801420b088092b8c398feffffff014a060880"
                      "eeb4d30652483046022100c007b801dc840a32c583e14c2def737d0c5e0621056b65bf80"
                      "3fb6cd6321c0b3022100aa17000c68f22ea56e689723f8ce061545277e731a8f5000be30"
                      "7afd07f9c160620b088092b8c398feffffff016a2054e6ff35e4e6b5d63035c97f992d67"
                      "abf71dbd63f2f221ccaedc0df3033d0de0")))

(def upload-chunk-1
  (unhex "1a121210a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))

(def upload-chunk-2
  (unhex "1a1c08101218b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7"))

(def upload-done
  (unhex (str "2290010a20707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e"
                     "8f12200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f201a"
                     "402c9dabf5c67cb83c0ff5d6b018ac4f4fd6ff099487c22a27527fc1eab57b3010a001cb"
                     "feaae5fc586e584391f605f030b4c8d83b3979c0a78b080cfa304cd80020282a060880a8"
                     "aad306")))

(def data
  (unhex (str "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3"
              "c4c5c6c7")))

(def download-first
  (unhex (str "0a89020a100202030405060708090a0b0c0d0e0f101220101112131415161718191a1b1c"
                        "1d1e1f202122232425262728292a2b2c2d2e2f2220404142434445464748494a4b4c4d4e"
                        "4f505152535455565758595a5b5c5d5e5f2a20707172737475767778797a7b7c7d7e7f80"
                        "8182838485868788898a8b8c8d8e8f30403802420b088092b8c398feffffff014a060880"
                        "eeb4d30652473045022073d3523c0d1bcec546c65f5bc738228ee3eda1861affdeae6616"
                        "a41d03054c5c022100862b3576615600287bcd085a14927cdf56b0b70b19396bdc3ab88e"
                        "b7c345b563620b088092b8c398feffffff016a2054e6ff35e4e6b5d63035c97f992d67ab"
                        "f71dbd63f2f221ccaedc0df3033d0de01a0408081010")))

(def download-wrong-action
  (unhex (str "0a8a020a100102030405060708090a0b0c0d0e0f101220101112131415161718191a1b1c"
                               "1d1e1f202122232425262728292a2b2c2d2e2f2220404142434445464748494a4b4c4d4e"
                               "4f505152535455565758595a5b5c5d5e5f2a20707172737475767778797a7b7c7d7e7f80"
                               "8182838485868788898a8b8c8d8e8f30403801420b088092b8c398feffffff014a060880"
                               "eeb4d30652483046022100c007b801dc840a32c583e14c2def737d0c5e0621056b65bf80"
                               "3fb6cd6321c0b3022100aa17000c68f22ea56e689723f8ce061545277e731a8f5000be30"
                               "7afd07f9c160620b088092b8c398feffffff016a2054e6ff35e4e6b5d63035c97f992d67"
                               "abf71dbd63f2f221ccaedc0df3033d0de01a0408081010")))

(def download-too-big
  (unhex (str "0a89020a100202030405060708090a0b0c0d0e0f101220101112131415161718191a1b1c"
                          "1d1e1f202122232425262728292a2b2c2d2e2f2220404142434445464748494a4b4c4d4e"
                          "4f505152535455565758595a5b5c5d5e5f2a20707172737475767778797a7b7c7d7e7f80"
                          "8182838485868788898a8b8c8d8e8f30403802420b088092b8c398feffffff014a060880"
                          "eeb4d30652473045022073d3523c0d1bcec546c65f5bc738228ee3eda1861affdeae6616"
                          "a41d03054c5c022100862b3576615600287bcd085a14927cdf56b0b70b19396bdc3ab88e"
                          "b7c345b563620b088092b8c398feffffff016a2054e6ff35e4e6b5d63035c97f992d67ab"
                          "f71dbd63f2f221ccaedc0df3033d0de01a021041")))

(def order-limit-bytes 64)

(def expiration-unix 1785542400)

(def ^:private opts
  {:node-id       storage-node-id
   :satellite-key satellite-spki
   :algorithm     :ecdsa-sha256
   :verifier      v/verifier
   :clock         (reify p/IClock (-now-seconds [_] (dec expiration-unix)))})

(defn- decode [bs] (w/decode bs))

;; ── an upload that works ────────────────────────────────────────────────────

(deftest a-real-upload-is-admitted-and-reassembled
  (let [st (ps/begin-upload (decode upload-first) opts)]
    (is (:ok? st) (pr-str (:reasons st)))
    (is (= order-limit-bytes (:max-bytes st)))
    (is (= piece-id (:piece-id st)))
    (let [r1 (ps/accept-chunk st (decode upload-chunk-1))
          r2 (ps/accept-chunk (:state r1) (decode upload-chunk-2))
          fin (ps/finish-upload (:state r2) (decode upload-done))]
      (is (:ok? r1))
      (is (:ok? r2))
      (is (= data (into (:accepted r1) (:accepted r2)))
          "the bytes handed back are the piece, in order and complete")
      (is (:ok? fin) (pr-str (:reasons fin)))
      (is (= (count data) (:size fin)))
      (is (= 2 (:chunks fin))))))

(deftest the-hash-is-not-claimed-to-be-verified
  ;; the uplink signs `done` with its piece key, and checking that needs the
  ;; key out of the limit. Saying so is the difference between a node that has
  ;; not checked and a node that appears to have.
  (let [st  (ps/begin-upload (decode upload-first) opts)
        r1  (ps/accept-chunk st (decode upload-chunk-1))
        r2  (ps/accept-chunk (:state r1) (decode upload-chunk-2))
        fin (ps/finish-upload (:state r2) (decode upload-done))]
    (is (false? (:hash-verified? fin)))
    (is (some? (:signature fin)) "the signature is carried, just not checked")))

;; ── uploads that must not be ────────────────────────────────────────────────

(deftest the-first-message-has-to-carry-a-limit
  (let [r (ps/begin-upload (decode upload-chunk-1) opts)]
    (is (not (:ok? r)))
    (is (= [:first-message-has-no-limit] (mapv :reason (:reasons r))))))

(deftest a-second-limit-is-refused-rather-than-ignored
  ;; ignoring it leaves two readings of this stream disagreeing about what was
  ;; authorised
  (let [st (ps/begin-upload (decode upload-first) opts)
        r  (ps/accept-chunk st (decode upload-first))]
    (is (not (:ok? r)))
    (is (= :second-limit-in-one-upload (:reason (first (:reasons r)))))))

(deftest chunks-must-be-contiguous
  (let [st (ps/begin-upload (decode upload-first) opts)]
    (testing "a gap leaves a hole the uplink never sent"
      (let [r (ps/accept-chunk st (decode upload-chunk-2))]
        (is (not (:ok? r)))
        (is (= :chunk-out-of-order (:reason (first (:reasons r)))))
        (is (= 0 (:expected (first (:reasons r)))))
        (is (= 16 (:offset (first (:reasons r)))))))
    (testing "and an overlap rewrites bytes already counted"
      (let [r1 (ps/accept-chunk st (decode upload-chunk-1))
            r2 (ps/accept-chunk (:state r1) (decode upload-chunk-1))]
        (is (not (:ok? r2)))
        (is (= :chunk-out-of-order (:reason (first (:reasons r2)))))))))

(deftest the-limit-is-enforced-as-the-bytes-arrive
  ;; checked per chunk rather than at the end: at the end the bytes are
  ;; already in memory and the work is already done
  (let [st  (ps/begin-upload (decode upload-first) opts)
        big (w/encode [(w/message-field 3 [(w/varint-field 1 0)
                                           (w/bytes-field 2 (vec (repeat 65 0x41)))])])
        r   (ps/accept-chunk st (decode big))]
    (is (not (:ok? r)))
    (is (= :over-the-order-limit (:reason (first (:reasons r)))))
    (is (= order-limit-bytes (:limit (first (:reasons r)))))))

(deftest done-before-any-data-is-refused
  ;; The dangerous shape is a first message carrying *both* the limit and the
  ;; hash: a piece of length zero, signed as whatever the hash says. The two
  ;; messages concatenate because their fields have different numbers, which
  ;; is also how an uplink would send it.
  (let [both (into upload-first upload-done)
        r    (ps/begin-upload (decode both) opts)]
    (is (not (:ok? r)))
    (is (= [:done-before-any-data] (mapv :reason (:reasons r)))))
  (testing "and a done with no limit is refused for the plainer reason"
    (let [r (ps/begin-upload (decode upload-done) opts)]
      (is (not (:ok? r)))
      (is (= [:first-message-has-no-limit] (mapv :reason (:reasons r)))))))

(deftest a-message-after-done-is-refused
  (let [st  (ps/begin-upload (decode upload-first) opts)
        r1  (ps/accept-chunk st (decode upload-chunk-1))
        r2  (ps/accept-chunk (:state r1) (decode upload-chunk-2))
        fin (ps/finish-upload (:state r2) (decode upload-done))
        after (ps/accept-chunk (:state fin) (decode upload-chunk-1))]
    (is (not (:ok? after)))
    (is (= :message-after-done (:reason (first (:reasons after)))))))

(deftest a-done-that-names-another-piece-is-refused
  (let [st  (ps/begin-upload (decode upload-first) opts)
        r1  (ps/accept-chunk st (decode upload-chunk-1))
        elsewhere (w/encode [(w/message-field 4 [(w/bytes-field 1 (vec (repeat 32 0xee)))])])
        fin (ps/finish-upload (:state r1) (decode elsewhere))]
    (is (not (:ok? fin)))
    (is (= :done-names-another-piece (:reason (first (:reasons fin)))))))

(deftest a-declared-size-that-is-not-what-arrived-is-refused
  (let [st  (ps/begin-upload (decode upload-first) opts)
        r1  (ps/accept-chunk st (decode upload-chunk-1))
        lying (w/encode [(w/message-field 4 [(w/bytes-field 1 piece-id)
                                             (w/varint-field 4 999)])])
        fin (ps/finish-upload (:state r1) (decode lying))]
    (is (not (:ok? fin)))
    (is (= :declared-size-is-not-what-arrived (:reason (first (:reasons fin)))))
    (is (= 999 (:declared (first (:reasons fin)))))
    (is (= 16 (:received (first (:reasons fin)))))))

(deftest an-order-without-a-chunk-is-not-an-error
  ;; the uplink is paying as it goes
  (let [st (ps/begin-upload (decode upload-first) opts)
        order-only (w/encode [(w/message-field 2 [(w/varint-field 2 16)])])
        r (ps/accept-chunk st (decode order-only))]
    (is (:ok? r))
    (is (= [] (:accepted r)))
    (is (= 0 (:received (:state r))) "and it does not move the offset")))

;; ── downloading ─────────────────────────────────────────────────────────────

(deftest a-real-download-is-admitted
  (let [d (ps/begin-download (decode download-first) opts)]
    (is (:ok? d) (pr-str (:reasons d)))
    (is (= 8 (:offset d)))
    (is (= 16 (:size d)))))

(deftest a-put-limit-cannot-serve-a-download
  ;; the action is part of what the satellite signed
  (let [d (ps/begin-download (decode download-wrong-action) opts)]
    (is (not (:ok? d)))
    (is (= [:action-mismatch] (mapv :reason (:reasons d))))))

(deftest a-range-past-the-limit-is-refused
  (let [d (ps/begin-download (decode download-too-big) opts)]
    (is (not (:ok? d)))
    (is (= :range-exceeds-the-order-limit (:reason (first (:reasons d)))))))

(deftest a-download-does-not-send-more-than-was-asked-for
  ;; checked before the write rather than after: a node that notices
  ;; afterwards has already sent them
  (let [d  (ps/begin-download (decode download-first) opts)
        s1 (ps/sending d 10)
        s2 (ps/sending (:state s1) 10)]
    (is (:ok? s1))
    (is (not (:ok? s2)))
    (is (= :more-than-was-requested (:reason (first (:reasons s2)))))
    (testing "and exactly the right amount is allowed"
      (let [s2' (ps/sending (:state s1) 6)]
        (is (:ok? s2'))
        (is (ps/download-complete? (:state s2')))))))

(deftest a-download-response-carries-its-offset
  (let [bs (ps/download-chunk-response 8 [1 2 3])
        chunk (w/message-value (w/field (w/decode bs) 1))]
    (is (= 8 (w/varint-value (w/field chunk 1))))
    (is (= [1 2 3] (w/bytes-value (w/field chunk 2))))))
