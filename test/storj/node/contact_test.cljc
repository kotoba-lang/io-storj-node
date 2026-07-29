(ns storj.node.contact-test
  "Check-in, against what `pb.Marshal` produces for the same message.

  The request is the one worth holding to the reference implementation.
  Reasoning from a `.proto` is how one writes a message that encodes cleanly
  and means something else, and this file exists because that happened here:
  `NodeVersion.timestamp` is `nullable=false`, so gogo emits Go's zero time
  even when nothing set it, and the first version of `node-version` left the
  field out."
  (:require [clojure.test :refer [deftest is testing]]
            [proto.wire :as w]
            [storj.node.bytes :as b]
            [storj.node.contact :as contact]
            [storj.node.pb :as pb]))

(defn- unhex [s]
  (mapv #?(:clj  #(Integer/parseInt % 16)
           :cljs #(js/parseInt % 16))
        (re-seq #"[0-9a-fA-F]{2}" s)))

;; ── testdata/checkin-vectors.edn, generated — do not hand-edit ──────────────

(def check-in-request-bytes
  (unhex (str "0a0f3132372e302e302e313a323839363712180a07312e3130342e351a0b088092b8"
              "c398feffffff0120011a071080808080802022170a0e6f70406578616d706c652e63"
              "6f6d12053078616263")))

(def response-refused
  (unhex (str "12416661696c656420746f206469616c2073746f72616765206e6f6465202849443a"
              "2031616263292061742061646472657373203132372e302e302e313a3238393637")))

(def response-accepted (unhex "080118012001"))

(def ping-error-message
  "failed to dial storage node (ID: 1abc) at address 127.0.0.1:28967")

;; ── the request ─────────────────────────────────────────────────────────────

(def ^:private request-opts
  {:address  "127.0.0.1:28967"
   :version  {:version "1.104.5" :release? true}
   :capacity {:free-disk 1099511627776}
   :operator {:email "op@example.com" :wallet "0xabc"}})

(deftest a-check-in-request-is-byte-identical-to-pb-marshal
  (is (= check-in-request-bytes (contact/check-in-request request-opts))))

(deftest the-node-version-timestamp-is-emitted-even-when-nobody-set-one
  ;; (gogoproto.stdtime) with (gogoproto.nullable) = false: gogo marshals a
  ;; time.Time value rather than a pointer, and a zero time.Time is a value.
  ;; Leaving it out makes a request eleven bytes short of what a satellite
  ;; parses, which is the trap the order-limit timestamps set too.
  (let [fields (contact/node-version {:version "1.104.5"})
        ts     (w/field fields 3)]
    (is (some? ts))
    (is (= pb/go-zero-timestamp (w/bytes-value ts)))
    (is (= 11 (count (w/bytes-value ts))) "year 1, as a ten-byte varint plus its tag")))

(deftest the-deprecated-capacity-field-is-not-sent
  ;; free_bandwidth is field 1 and deprecated; filling it tells a satellite
  ;; something no satellite reads
  (let [fields (contact/node-capacity {:free-disk 42})]
    (is (nil? (w/field fields 1)))
    (is (= 42 (w/varint-value (w/field fields 2))))))

(deftest absent-is-not-empty
  ;; an empty embedded message is a field that *was* set — a satellite reading
  ;; one is being told this node has a noise key when it has none
  (let [bs (contact/check-in-request {:address "a"})
        msg (w/decode bs)]
    (is (nil? (pb/get-field msg pb/check-in-request :noise-key-attestation)))
    (is (nil? (pb/get-field msg pb/check-in-request :signed-tags)))
    (is (nil? (pb/get-field msg pb/check-in-request :version)))
    (is (= "a" (w/bytes->utf8 (pb/get-bytes msg pb/check-in-request :address))))))

(deftest wallet-features-repeat
  (let [fields (contact/node-operator {:email "e" :wallet-features ["zksync" "eth"]})
        repeated (filter #(= 3 (:field-number %)) fields)]
    (is (= 2 (count repeated)))
    (is (= ["zksync" "eth"] (mapv #(w/bytes->utf8 (:value %)) repeated)))))

;; ── the response ────────────────────────────────────────────────────────────

(deftest a-refusal-is-read-with-its-reason
  (let [r (contact/read-check-in-response (w/decode response-refused))]
    (is (false? (:ping-node-success r)))
    (is (= ping-error-message (:ping-error-message r)))
    (is (not (contact/admitted? r)))
    (is (= :ping-failed (:reason (contact/refusal r))))
    (is (= ping-error-message (:message (contact/refusal r))))))

(deftest an-acceptance-is-read-as-one
  (let [r (contact/read-check-in-response (w/decode response-accepted))]
    (is (true? (:ping-node-success r)))
    (is (true? (:ping-node-success-quic r)))
    (is (true? (:node-tag-success r)))
    (is (nil? (:ping-error-message r)))
    (is (contact/admitted? r))
    (is (nil? (contact/refusal r)))))

(deftest a-silent-refusal-still-says-something
  ;; ping_node_success false with no message at all: proto3 omits both, so the
  ;; whole response is zero bytes
  (let [r (contact/read-check-in-response (w/decode []))]
    (is (false? (:ping-node-success r)))
    (is (not (contact/admitted? r)))
    (is (= "the satellite gave no reason" (:message (contact/refusal r))))))

(deftest booleans-come-back-as-booleans
  ;; `(if (get r :ping-node-success) ...)` is true for 0, and every field in
  ;; this response is a decision the caller has to make
  (let [r (contact/read-check-in-response (w/decode response-refused))]
    (is (false? (:ping-node-success r)))
    (is (not= 0 (:ping-node-success r)))))

(deftest the-rpc-names-are-the-ones-storj-routes
  (is (= "/node.Node/CheckIn" contact/rpc)
      "the service is Node, not Contact")
  (is (= "/contact.Contact/PingNode" contact/ping-rpc)
      "and Contact is what the satellite calls back on the node"))

(deftest the-request-round-trips-through-the-schema
  (let [msg (w/decode (contact/check-in-request request-opts))]
    (is (= "127.0.0.1:28967" (w/bytes->utf8 (pb/get-bytes msg pb/check-in-request :address))))
    (testing "the nested messages are readable with their own schemas"
      (let [op (pb/get-msg msg pb/check-in-request :operator)]
        (is (= "op@example.com" (w/bytes->utf8 (pb/get-bytes op pb/node-operator :email))))
        (is (= "0xabc" (w/bytes->utf8 (pb/get-bytes op pb/node-operator :wallet)))))
      (let [cap (pb/get-msg msg pb/check-in-request :capacity)]
        (is (= 1099511627776 (pb/get-varint cap pb/node-capacity :free-disk)))))))

(deftest hex-of-the-request-is-stable
  ;; a cheap guard on the fixture above: if the generator is rerun and the
  ;; literal is not, this is what says so
  (is (= (b/hex check-in-request-bytes)
         (b/hex (contact/check-in-request request-opts)))))
