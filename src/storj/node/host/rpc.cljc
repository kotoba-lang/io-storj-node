(ns storj.node.host.rpc
  "A DRPC call on a verified Storj connection.

  The last joint. `storj.node.host.tls` produces a socket whose peer has been
  admitted by `storj.node.identity`; `drpc.client` says which packets a unary
  call is made of; this writes the one onto the other and reads the answer
  back.

  ## Why this is here and not in drpc

  `kotoba-lang/drpc` deliberately has no socket layer — it is bytes in, bytes
  out, so the same description drives a JVM stream, a Node socket, or a test
  that opens neither. Putting a reader loop there would give it a host layer
  and a reason to care about timeouts, which is the opposite of what makes it
  portable. What is here is the *joining*: a Storj TLS socket on one side and
  DRPC on the other, and both of those are already this repo's business.

  ## What it does not do

   answers calls on a socket the other way round, and it is
  the same shape: read, hand the decision somewhere else, write what comes
  back. Neither closes the socket.

  `serve-connection` answers calls on a socket the other way round, and it is
  the same shape: read, hand the decision somewhere else, write what comes
  back. Neither closes the socket.

  One call at a time, on a stream the caller names. DRPC multiplexes and this
  does not: a real node runs several calls over one connection and needs a
  reader that dispatches packets to whichever call is waiting. That is a
  scheduler, and writing one before there is a second caller would be
  guessing at what it needs."
  (:require [drpc.client :as c]
            [storj.node.protocols :as p]
            [drpc.server :as srv]
            [drpc.wire :as w]
            [storj.node.bytes :as b]
            #?(:cljs ["node:tls"]))
  #?(:clj (:import (java.net SocketTimeoutException))))

(def default-timeout-ms 20000)

(defn- fail [msg data]
  (throw (ex-info (str "storj.node.host.rpc: " msg) data)))

(defn call
  "Perform one unary DRPC call on `socket` and return the result.

      {:message bytes | nil
       :error   {:code n :message s} | nil
       :closed? bool
       :ignored [packets on other streams]}

  `opts`: `:rpc` (required), `:request` (encoded request bytes), `:stream`,
  `:metadata`, `:timeout-ms`.

  On cljs this returns a promise; on the JVM it blocks. Neither closes the
  socket — a connection outlives a call, and closing one here would make the
  common case (several calls to the same satellite) impossible to write."
  [socket {:keys [rpc request stream timeout-ms]
           :or   {stream c/first-stream timeout-ms default-timeout-ms}
           :as   opts}]
  (let [stream  stream
        payload (c/request (assoc opts :stream stream :rpc rpc
                                  :request (vec request)))]
    #?(:clj
       (let [out (.getOutputStream socket)
             in  (.getInputStream socket)]
         (.setSoTimeout socket (int timeout-ms))
         (.write out (b/->native payload))
         (.flush out)
         (loop [state (w/reader), seen []]
           (let [buf (byte-array 8192)
                 n   (try (.read in buf)
                          (catch SocketTimeoutException _
                            (fail "timed out waiting for a response"
                                  {:rpc rpc :timeout-ms timeout-ms})))]
             (if (neg? n)
               ;; the peer hung up: whatever arrived is the whole answer, and
               ;; `collect` will report it as closed with no message
               (c/collect seen stream)
               (let [fed  (w/feed state (take n (seq buf)))
                     seen (into seen (:packets fed))
                     r    (c/collect seen stream)]
                 (if (c/complete? r) r (recur (:state fed) seen)))))))

       :cljs
       (js/Promise.
        (fn [resolve reject]
          (let [state (atom (w/reader))
                seen  (atom [])
                timer (js/setTimeout
                       (fn [] (reject (try (fail "timed out waiting for a response"
                                                 {:rpc rpc :timeout-ms timeout-ms})
                                           (catch :default e e))))
                       timeout-ms)
                finish (fn [r] (js/clearTimeout timer) (resolve r))
                on-data (fn on-data [chunk]
                          ;; not `{:keys [state ...]}`: that binding would
                          ;; shadow the atom of the same name and `reset!`
                          ;; would be handed the map — a mistake this repo has
                          ;; already made once, on this exact shape
                          (let [fed (w/feed @state chunk)]
                            (reset! state (:state fed))
                            (swap! seen into (:packets fed))
                            (let [r (c/collect @seen stream)]
                              (when (c/complete? r)
                                (.removeListener socket "data" on-data)
                                (finish r)))))]
            (.on socket "data" on-data)
            (.once socket "end" #(finish (c/collect @seen stream)))
            (.once socket "error" (fn [e] (js/clearTimeout timer) (reject e)))
            (.write socket (b/->native payload))))))))

(defn -put-seed
  "Put a zero-length blob at `path`.

  A convenience for harnesses that need a node to *hold* something before any
  rpc that stores one exists. Named with a leading dash as a reminder that it
  is scaffolding, not part of how a node acquires pieces."
  [store path]
  (p/-put store path []))

(defn ok?
  "Whether a call returned a response rather than an error or a hangup."
  [result]
  (boolean (and (:message result) (nil? (:error result)))))

;; ── being asked ─────────────────────────────────────────────────────────────

(defn serve-connection
  "Answer calls on `socket` until the peer goes away.

  `handle` is called with `{:stream :rpc :request}` and returns
  `{:response bytes}` or `{:error {:code n :message s}}` —
  `storj.node.service/handle` has that shape. Whatever it returns is written
  back; whatever it throws is not, because a handler that takes the
  connection with it turns one bad request into a disconnected node.

  Blocks on the JVM and returns a promise on cljs, and neither closes the
  socket: the peer decides when it is done."
  [socket handle]
  #?(:clj
     (let [in  (.getInputStream socket)
           out (.getOutputStream socket)]
       (loop [state (srv/incoming), answered 0]
         (let [buf (byte-array 8192)
               n   (.read in buf)]
           (if (neg? n)
             answered
             (let [{:keys [state calls]} (srv/feed state (take n (seq buf)))]
               (doseq [call calls]
                 (let [{:keys [response error]} (handle call)]
                   (.write out (b/->native (if error
                                             (srv/respond-error (:stream call)
                                                                (:code error)
                                                                (:message error))
                                             (srv/respond (:stream call) response))))
                   (.flush out)))
               (recur state (+ answered (count calls))))))))

     :cljs
     (js/Promise.
      (fn [resolve reject]
        (let [state (atom (srv/incoming))
              answered (atom 0)]
          (.on socket "data"
               (fn [chunk]
                 ;; not `{:keys [state ...]}` — that binding shadows the atom
                 (let [fed (srv/feed @state chunk)]
                   (reset! state (:state fed))
                   (doseq [call (:calls fed)]
                     (let [{:keys [response error]} (handle call)]
                       (.write socket (b/->native (if error
                                                    (srv/respond-error (:stream call)
                                                                       (:code error)
                                                                       (:message error))
                                                    (srv/respond (:stream call) response))))
                       (swap! answered inc))))))
          (.once socket "end" #(resolve @answered))
          (.once socket "error" reject))))))
