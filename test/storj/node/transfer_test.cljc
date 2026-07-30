(ns storj.node.transfer-test
  "Uploads and downloads as streams.

  The order limit here is the one `orders_test` uses — a real encoded
  `OrderLimit` — so admission is exercised rather than stubbed out. Only the
  signature check is a stub, because producing a satellite's signature would
  mean holding a satellite's key."
  (:require [clojure.string]
            [clojure.test :refer [deftest is testing]]
            [proto.wire :as w]
            [storj.node.bytes :as b]
            [storj.node.host.blobs :as blobs]
            [storj.node.pb :as pb]
            [storj.node.protocols :as p]
            [storj.node.transfer :as tr]))

(defn- unhex [s]
  (mapv #?(:clj #(Integer/parseInt % 16) :cljs #(js/parseInt % 16))
        (re-seq #"[0-9a-fA-F]{2}" s)))

(def ^:private order-limit-hex
  (str "0a100102030405060708090a0b0c0d0e0f10"
       "1220101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
       "2220404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
       "2a20707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
       "308080403801"
       "420b088092b8c398feffffff01"
       "4a0608c0b3a2d306"
       "5204deadbeef"
       "620608b097a2d306"
       "6a20a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"))

(def ^:private this-node
  (unhex "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"))

(def ^:private piece-id
  "the piece_id inside that limit — field 5, `pb/order-limit`.

  Not field 2, which is the satellite id. Reading the limit's fields in
  written order and calling the second one the piece id is the mistake the
  first draft of this file made; `orders/admit` was right and the constant
  here was wrong, which is the direction worth noticing."
  (unhex "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"))

(def ^:private order-expiry 1785240000)

(defn- clock-at [t] (reify p/IClock (-now-seconds [_] t)))
(defn- verifier [answer] (reify p/IVerifier (-verify [_ _ _ _ _] answer)))

(defn- ctx
  ([] (ctx {}))
  ([over]
   (merge {:node-id       this-node
           :satellite-key [0x01]
           :clock         (clock-at (- order-expiry 60))
           :verifier      (verifier true)
           :blobs         (blobs/in-memory)
           :paths         (fn [id] (str "p/" (b/hex id)))}
          over)))

;; ── the messages an uplink sends ────────────────────────────────────────────

(defn- first-upload-msg
  ([] (first-upload-msg nil))
  ([chunk-bytes]
   (w/encode (cond-> [(w/bytes-field 1 (unhex order-limit-hex))]
               chunk-bytes
               (conj (w/message-field 3 [(w/varint-field 1 0)
                                         (w/bytes-field 2 (vec chunk-bytes))]))))))

(defn- chunk-msg [offset bs]
  (w/encode [(w/message-field 3 [(w/varint-field 1 offset)
                                 (w/bytes-field 2 (vec bs))])]))

(defn- done-msg [{:keys [size hash id]}]
  ;; pb/piece-hash: 1 piece-id, 2 hash, 3 signature, 4 piece-size. Not in
  ;; order, and putting the size in 2 encodes cleanly and means the hash.
  (w/encode [(w/message-field 4 (cond-> []
                                  id   (conj (w/bytes-field 1 (vec id)))
                                  hash (conj (w/bytes-field 2 (vec hash)))
                                  size (conj (w/varint-field 4 size))))]))

(def ^:private get-limit-hex
  "The same limit with `action` switched from PUT to GET.

  `pb/piece-action` is `{1 :put 2 :get}` and the action is field 7, so the
  last byte of `3801` becomes 02. A download presented with the PUT limit is
  refused for `:action-mismatch`, which is admission working — the test needs
  a limit that authorises what it is asking for."
  (clojure.string/replace order-limit-hex "308080403801" "308080403802"))

(defn- download-msg [offset size & [max-chunk]]
  (w/encode (cond-> [(w/bytes-field 1 (unhex get-limit-hex))
                     (w/message-field 3 [(w/varint-field 1 offset)
                                         (w/varint-field 2 size)])]
              max-chunk (conj (w/varint-field 4 max-chunk)))))

(defn- feed
  "Drive a sequence of messages on one stream, collecting every `:out`."
  [c msgs & [rpc]]
  (loop [state (tr/transfers), [m & more] msgs, out []]
    (if (nil? m)
      {:state state :out out}
      (let [r (tr/message state c {:stream 1 :rpc (or rpc tr/upload-rpc) :data m})]
        (recur (:state r) more (into out (:out r)))))))

(defn- errors [out] (keep :error out))
(defn- messages [out] (keep :message out))

;; ── uploading ───────────────────────────────────────────────────────────────

(deftest an-upload-lands-in-the-store
  (let [c    (ctx)
        body (vec (range 100))
        r    (feed c [(first-upload-msg)
                      (chunk-msg 0 (subvec body 0 40))
                      (chunk-msg 40 (subvec body 40))
                      (done-msg {:size 100 :id piece-id})])]
    (is (empty? (errors (:out r))) (pr-str (errors (:out r))))
    (testing "the uplink is answered and the stream ends"
      (is (= 1 (count (messages (:out r)))))
      (is (some :end (:out r))))
    (testing "and the bytes are there, in order"
      (is (= body (p/-get (:blobs c) ((:paths c) piece-id)))))
    (testing "with nothing left open"
      (is (empty? (:state r))))))

(deftest the-first-message-may-carry-data
  (let [c (ctx)
        r (feed c [(first-upload-msg [1 2 3])
                   (done-msg {:size 3 :id piece-id})])]
    (is (empty? (errors (:out r))))
    (is (= [1 2 3] (p/-get (:blobs c) ((:paths c) piece-id))))))

(deftest the-node-answers-with-a-piece-hash-it-has-not-signed
  ;; an uplink reads this to learn the node accepted what it sent. It is
  ;; unsigned — see the upload-response docstring — and that is visible here
  ;; rather than left to be discovered by whoever checks one.
  (let [c (ctx)
        r (feed c [(first-upload-msg [7 7 7])
                   (done-msg {:size 3 :id piece-id})])
        resp (w/decode (first (messages (:out r))))
        done (pb/get-msg resp pb/piece-upload-response :done)]
    (is (= piece-id (pb/get-bytes done pb/piece-hash :piece-id)))
    (is (= 3 (pb/get-varint done pb/piece-hash :piece-size)))
    (is (nil? (pb/get-bytes done pb/piece-hash :signature))
        "no signature rather than an invented one")))

(deftest an-upload-nobody-authorised-stores-nothing
  (let [c (ctx {:verifier (verifier false)})
        r (feed c [(first-upload-msg [1 2 3])
                   (chunk-msg 3 [4 5])])]
    (is (seq (errors (:out r))))
    (is (nil? (p/-get (:blobs c) ((:paths c) piece-id)))
        "nothing was written on the way to finding out")))

(deftest a-done-naming-another-piece-stores-nothing
  (let [c (ctx)
        r (feed c [(first-upload-msg [1 2 3])
                   (done-msg {:size 3 :id (vec (repeat 32 0x99))})])]
    (is (seq (errors (:out r))))
    (is (nil? (p/-get (:blobs c) ((:paths c) piece-id))))))

(deftest a-declared-size-that-did-not-arrive-stores-nothing
  (let [c (ctx)
        r (feed c [(first-upload-msg [1 2 3])
                   (done-msg {:size 99 :id piece-id})])]
    (is (seq (errors (:out r))))
    (is (nil? (p/-get (:blobs c) ((:paths c) piece-id))))))

(deftest a-second-limit-mid-stream-is-refused
  ;; ignoring it would leave two readings of this stream disagreeing about
  ;; what was authorised
  (let [c (ctx)
        r (feed c [(first-upload-msg [1 2 3])
                   (first-upload-msg [4 5 6])])]
    (is (seq (errors (:out r))))))

;; ── downloading ─────────────────────────────────────────────────────────────

(defn- stored
  "A context whose store already holds `body` for this piece."
  [body]
  (let [c (ctx)]
    (p/-put (:blobs c) ((:paths c) piece-id) body)
    c))

(deftest a-download-comes-back-in-several-messages
  (let [body (vec (range 100))
        c    (stored body)
        r    (feed c [(download-msg 0 100 30)] tr/download-rpc)
        outs (messages (:out r))]
    (is (empty? (errors (:out r))) (pr-str (errors (:out r))))
    (is (= 4 (count outs)) "30 + 30 + 30 + 10")
    (is (some :end (:out r)))
    (testing "and reassemble to what was stored, at the right offsets"
      (let [chunks (map #(let [m (w/decode %)
                               ch (pb/get-msg m pb/piece-download-response :chunk)]
                           {:offset (or (pb/get-varint ch pb/download-response-chunk :offset) 0)
                            :data (pb/get-bytes ch pb/download-response-chunk :data)})
                        outs)]
        (is (= [0 30 60 90] (map :offset chunks)))
        (is (= body (vec (mapcat :data chunks))))))))

(deftest a-download-counts-what-it-sent
  ;; `piecestore/sending` cannot refuse in this implementation — the slice is
  ;; already the authorised range, see the comment where it is called — so
  ;; what it earns its place with is the count. Asserting the count is what
  ;; makes removing it fail; asserting only the refusal would not.
  (let [c (stored (vec (range 100)))
        r (tr/message (tr/transfers) c
                      {:stream 1 :rpc tr/download-rpc :data (download-msg 0 100 30)})]
    (is (= 100 (:sent r)))))

(deftest a-download-of-part-of-a-piece
  (let [body (vec (range 100))
        c    (stored body)
        r    (feed c [(download-msg 10 20 100)] tr/download-rpc)
        m    (w/decode (first (messages (:out r))))
        ch   (pb/get-msg m pb/piece-download-response :chunk)]
    (is (= 10 (pb/get-varint ch pb/download-response-chunk :offset)))
    (is (= (subvec body 10 30) (pb/get-bytes ch pb/download-response-chunk :data)))))

(deftest a-piece-this-node-lost-is-not-a-permission-answer
  ;; the limit authorised it; the node does not have it. A satellite reading
  ;; this as a refusal would blame the uplink.
  (let [c (ctx)
        r (feed c [(download-msg 0 10)] tr/download-rpc)]
    (is (= ["no such piece"] (map :message (errors (:out r)))))))

(deftest a-range-outside-the-limit-sends-nothing
  (let [c (stored (vec (range 100)))
        ;; the limit authorises 1 MiB; ask for more
        r (feed c [(download-msg 0 (* 2 1024 1024))] tr/download-rpc)]
    (is (seq (errors (:out r))))
    (is (empty? (messages (:out r))) "refused before a byte went out")))

(deftest an-empty-range-is-refused
  (let [c (stored (vec (range 10)))
        r (feed c [(download-msg 0 0)] tr/download-rpc)]
    (is (seq (errors (:out r))))))

;; ── the round trip ──────────────────────────────────────────────────────────

(deftest what-goes-up-comes-back
  (let [c    (ctx)
        body (vec (map #(mod (* % 7) 256) (range 300)))
        up   (feed c [(first-upload-msg)
                      (chunk-msg 0 (subvec body 0 128))
                      (chunk-msg 128 (subvec body 128 256))
                      (chunk-msg 256 (subvec body 256))
                      (done-msg {:size 300 :id piece-id})])
        down (feed c [(download-msg 0 300 128)] tr/download-rpc)]
    (is (empty? (errors (:out up))) (pr-str (errors (:out up))))
    (is (empty? (errors (:out down))) (pr-str (errors (:out down))))
    (is (= body
           (vec (mapcat #(-> (w/decode %)
                             (pb/get-msg pb/piece-download-response :chunk)
                             (pb/get-bytes pb/download-response-chunk :data))
                        (messages (:out down)))))
        "including the bytes above 127, which a signed byte would report negative")))

;; ── routing ─────────────────────────────────────────────────────────────────

(deftest the-streaming-rpcs-are-the-ones-service-does-not-serve
  ;; a dispatcher that fell through to service/handle for these would answer
  ;; an upload with `unimplemented`
  (is (tr/streaming? tr/upload-rpc))
  (is (tr/streaming? tr/download-rpc))
  (is (not (tr/streaming? "/contact.Contact/PingNode")))
  (is (not (tr/streaming? "/piecestore.Piecestore/Exists"))))

(deftest a-message-on-an-rpc-this-does-not-stream-is-an-error-not-a-crash
  (let [r (tr/message (tr/transfers) (ctx)
                      {:stream 1 :rpc "/piecestore.Piecestore/Exists" :data []})]
    (is (seq (errors (:out r))))))

(deftest a-malformed-message-ends-one-stream-and-not-the-connection
  (let [c (ctx)
        r (tr/message (tr/transfers) c
                      {:stream 1 :rpc tr/upload-rpc :data [0xff 0xff 0xff]})]
    (is (seq (errors (:out r))))
    (is (empty? (:state r)) "and the stream is not left open")))
