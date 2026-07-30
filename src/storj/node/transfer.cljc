(ns storj.node.transfer
  "Upload and Download as streams — the part `storj.node.service` could not
  hold.

  `service` answers one request with one response, which is the whole unary
  surface and none of the transfers. `storj.node.piecestore` has decided what
  an upload and a download are allowed to be since before there was anything
  to drive it: `begin-upload`, `accept-chunk`, `finish-upload`,
  `begin-download`, `sending`. This is what drives it, one message at a time.

  ## What this returns, and what it does not do

  `{:state s :out [...]}`, where each entry of `:out` is `{:message bytes}`,
  `{:end true}` or `{:error {:code n :message s}}`. No DRPC framing: that
  lives in `drpc.server` and `storj.node.host.rpc`, and a second place that
  knew how to write a packet would be a second place to get message ids
  wrong. Nothing here touches a socket either — a stream that ends is a value
  saying so.

  ## One message at a time is the point

  `drpc.server/feed` hands over `:messages` as they arrive rather than
  waiting for the client to finish, precisely so an upload does not have to
  be complete before a node can act on it. This uses that.

  It then buffers anyway, and the reason is worth stating rather than
  discovering: `IBlobStore/-put` takes a whole blob. So a piece is held in
  memory until `done`, which is a limit of that protocol and not of this
  layer or the transport — the streaming is real up to the store, and stops
  there. A node that must not hold a piece in memory needs `-put` to grow an
  offset, and then this changes in one place.

  ## What lands in the store is a body, not a piece file

  An upload writes the payload and nothing else, which is storage format
  **V0** — `piece/body-offset :v0` is zero and reads start there. A real node
  writes V1: a 512-byte reserved area holding a `PieceHeader` with the
  uplink's signed hash, so a restarted node can still prove what it holds.
  `piece/encode-header` can build one and nothing here calls it, because the
  hash it would carry is the one `finish-upload` reports as
  `:hash-verified? false`. Writing an unverified hash into a header a node
  later offers as proof is worse than not writing the header. `ctx` takes
  `:format` so a caller that does write V1 is read correctly.

  ## A refused transfer is an error on that stream, not a closed connection

  A node is reachable by anyone who completed a handshake. An upload that
  fails admission ends *its* stream with an error and leaves every other
  stream on the connection alone, which is the same rule `service/handle`
  follows for the unary side."
  (:require [proto.wire :as w]
            [storj.node.pb :as pb]
            [storj.node.piece :as piece]
            [storj.node.piecestore :as ps]
            [storj.node.protocols :as p]))

(def upload-rpc   "/piecestore.Piecestore/Upload")
(def download-rpc "/piecestore.Piecestore/Download")

(def streaming-rpcs
  "The two rpcs that are not request-and-response.

  `service/handlers` deliberately does not contain these, and a dispatcher
  that fell back to it for them would answer an upload with
  `unimplemented` — so the split has to be visible to whoever routes."
  #{upload-rpc download-rpc})

(defn streaming? [rpc] (contains? streaming-rpcs rpc))

(def transfer-error-code
  "The code a refused transfer travels under. `drpcerr` gives no named
  constant, and zero means no error at all, so this is the same non-zero
  choice `service/unimplemented-code` makes for the same reason."
  2)

(defn transfers
  "The state a connection keeps for its open transfers: stream id → transfer."
  []
  {})

(defn- refuse
  "End one stream with a reason a caller can act on.

  The reasons come from `piecestore`/`orders` as data; they are rendered here
  because the wire carries a string and nothing else."
  [state stream reasons]
  {:state (dissoc state stream)
   :out   [{:error {:code transfer-error-code
                    :message (str "transfer refused: "
                                  (pr-str (mapv :reason reasons)))}}]})

;; ── uploading ───────────────────────────────────────────────────────────────

(defn- upload-response
  "`PieceUploadResponse`. The node's own `done` — a `PieceHash` naming the
  piece and its size.

  Unsigned, and that is a real gap rather than an omission: an uplink checks
  this signature to know the node accepted what it thinks it sent. Signing
  needs this node's key through `IKeyMaterial`, the same seam minting uses.
  Sending an unsigned one is honest about what has happened; sending a
  fabricated signature would not be."
  [{:keys [piece-id size hash hash-algorithm]}]
  ;; the numbers are `pb/piece-hash`, and they are not in order: 2 is the
  ;; hash, 3 is the signature, and the size is 4. Writing the size into 2 —
  ;; which is what the first draft of this did — produces a message that
  ;; encodes cleanly and tells an uplink its piece hashed to a number.
  (w/encode
   [(w/message-field 1 (cond-> []
                         piece-id (conj (w/bytes-field 1 (vec piece-id)))
                         hash     (conj (w/bytes-field 2 (vec hash)))
                         size     (conj (w/varint-field 4 size))
                         hash-algorithm
                         (conj (w/varint-field 6 (pb/enum-value
                                                  pb/piece-hash-algorithm
                                                  hash-algorithm)))))]))

(defn- begin-upload [state ctx stream msg]
  (let [r (ps/begin-upload msg ctx)]
    (if-not (:ok? r)
      (refuse state stream (:reasons r))
      {:state (assoc state stream {:kind :upload
                                   :upload r
                                   :buffer (vec (:accepted r))})
       :out   []})))

(defn- continue-upload
  "One more message on an open upload: a chunk, or the `done` that ends it."
  [state ctx stream {:keys [upload buffer]} msg]
  (if (:done (ps/upload-parts msg))
    (let [r (ps/finish-upload upload msg)]
      (if-not (:ok? r)
        (refuse state stream (:reasons r))
        (do
          ;; the store is reached only once every rule has answered yes
          (p/-put (:blobs ctx) ((:paths ctx) (:piece-id r)) buffer)
          {:state (dissoc state stream)
           :out   [{:message (upload-response r)} {:end true}]
           :stored r})))
    (let [r (ps/accept-chunk upload msg)]
      (if-not (:ok? r)
        (refuse state stream (:reasons r))
        {:state (assoc state stream {:kind :upload
                                     :upload (:state r)
                                     :buffer (into buffer (:accepted r))})
         :out   []}))))

;; ── downloading ─────────────────────────────────────────────────────────────

(def default-chunk-size
  "How much goes in one `PieceDownloadResponse` when the client did not say.

  Storj's own uplink asks for a maximum; this is only what happens when it
  does not. Small enough that a download is visibly several messages, which
  is the property being exercised."
  262144)

(defn- serve-download
  "Read the range and hand back the messages that carry it.

  The whole range is read from the store here for the same reason an upload
  buffers: `IBlobStore/-get` returns a whole blob. The chunking below is real
  — a client sees several messages — but the read behind it is not yet."
  [state ctx stream msg]
  (let [r (ps/begin-download msg ctx)]
    (if-not (:ok? r)
      (refuse state stream (:reasons r))
      (let [blob (p/-get (:blobs ctx) ((:paths ctx) (:piece-id r)))]
        (if (nil? blob)
          ;; the limit authorised it and this node does not have it. Not a
          ;; permission answer — a satellite reading this one as refusal
          ;; would blame the uplink for a piece the node lost.
          {:state (dissoc state stream)
           :out   [{:error {:code transfer-error-code
                            :message "no such piece"}}]}
          (let [body   (piece/body-offset (:format ctx :v0))
                want   (or (pb/get-varint msg pb/piece-download-request
                                          :maximum-chunk-size)
                           default-chunk-size)
                size   (max 1 (min want (:size r)))
                slice  (subvec (vec blob)
                               (min (count blob) (+ body (:offset r)))
                               (min (count blob) (+ body (:offset r) (:size r))))
                pieces (partition-all size slice)]
            (loop [acc [] st r offset (:offset r) [c & more] pieces]
              (if (nil? c)
                {:state (dissoc state stream)
                 :out   (conj acc {:end true})
                 :sent  (:sent st)}
                ;; `sending` cannot refuse here, because the slice above is
                ;; already exactly the authorised range — that is worth
                ;; saying rather than leaving as a guard a reader assumes is
                ;; the bound. What it does provide is `:sent`, which is the
                ;; count this reports. Kept rather than dropped because the
                ;; day this streams from the store instead of slicing a whole
                ;; blob, the slice stops being the bound and this becomes it.
                (let [s (ps/sending st (count c))]
                  (if-not (:ok? s)
                    (refuse state stream (:reasons s))
                    (recur (conj acc {:message (ps/download-chunk-response offset c)})
                           (:state s)
                           (+ offset (count c))
                           more)))))))))))

;; ── the one entry point ─────────────────────────────────────────────────────

(defn message
  "Drive one message of a streaming rpc.

  `ctx` is what `piecestore` and the store need: `:blobs`, `:paths`,
  `:node-id`, and whatever `orders/admit` reads. Returns `{:state s :out
  [...]}` and never throws for anything a peer can send — the caller is
  reachable by whoever completed a handshake."
  [state ctx {:keys [stream rpc data]}]
  (try
    (let [open (get state stream)
          msg  (w/decode data)]
      (cond
        open                (continue-upload state ctx stream open msg)
        (= rpc upload-rpc)  (begin-upload state ctx stream msg)
        (= rpc download-rpc) (serve-download state ctx stream msg)
        :else
        {:state state
         :out   [{:error {:code transfer-error-code
                          :message (str "not a streaming rpc: " rpc)}}]}))
    (catch #?(:clj Exception :cljs :default) e
      {:state (dissoc state stream)
       :out   [{:error {:code transfer-error-code
                        :message (str "storj.node.transfer: " rpc " failed: "
                                      (or #?(:clj (ex-message e)
                                             :cljs (.-message e))
                                          "unknown"))}}]})))
