(ns tls-peer
  "A Storj TLS peer built out of this library, mirroring `testdata/tls_peer.go`
  so the two can be pointed at each other.

      clojure -M:tls-peer serve /tmp/id-a 19443
      clojure -M:tls-peer dial  /tmp/id-b 127.0.0.1:19443 <expected-hex>
      clojure -M:tls-peer call  /tmp/id-b 127.0.0.1:19443 <expected-hex> \\
        /echo.Echo/Echo hello
      nbb --classpath \"$(clojure -A:cljs -Spath)\" scripts/tls_peer.cljc \\
        dial /tmp/id-b 127.0.0.1:19443 <expected-hex>

  In serve mode it prints `listening <port>` once bound, then accepts one
  connection, prints the peer's node id and exits — the same contract the Go
  peer follows, so CI can drive either side with either implementation.

  This is a test harness, not part of the library: nothing under `src/`
  requires it, and `scripts/` is not on `:paths`."
  (:require [clojure.string :as str]
            [drpc.client :as drpc]
            [storj.node.bytes :as b]
            [storj.node.host.rpc :as rpc]
            [storj.node.host.keys :as hk]
            [storj.node.host.tls :as htls]
            [storj.node.identity :as ident]
            #?(:cljs ["node:fs" :as fs])))

(defn- slurp* [path]
  #?(:clj (slurp path) :cljs (fs/readFileSync path "utf8")))

(defn- unhex [s]
  (mapv #?(:clj  #(Integer/parseInt % 16)
           :cljs #(js/parseInt % 16))
        (re-seq #"[0-9a-fA-F]{2}" s)))

(defn load-identity
  "An identity directory, in the form `storj.node.host.tls` wants.

  The leaf key, not the CA key: `identity.key` is what signs on the wire,
  while the CA key stays offline once the identity exists."
  [dir]
  (let [chain (ident/parse-chain-pem (slurp* (str dir "/identity.cert")))
        key   (ident/parse-private-key-pem (slurp* (str dir "/identity.key")))]
    {:chain chain
     :private-key (hk/import-private-key (:der key) (:encoding key))}))

(def greeting
  "Exchanged after the handshake so that both peers have to finish it, rather
  than one of them merely believing it did. On TLS 1.3 a client that hangs up
  straight after its own Finished leaves the server reporting EOF while the
  client reports success — which is exactly what happened the first time this
  harness was run against the Go peer."
  "storj\n")

(defn- exchange!
  "`:serve` writes the greeting and reads it back; `:dial` reads it and echoes.
  Returns a promise on cljs and blocks on the JVM."
  [socket role]
  #?(:clj
     (let [out (.getOutputStream socket)
           in  (.getInputStream socket)
           buf (byte-array (count greeting))
           read-all (fn []
                      (loop [off 0]
                        (when (< off (count greeting))
                          (let [n (.read in buf off (- (count greeting) off))]
                            (when (neg? n) (throw (ex-info "tls-peer: closed early" {})))
                            (recur (+ off n))))))]
       (if (= :serve role)
         (do (.write out (.getBytes greeting "UTF-8")) (.flush out) (read-all))
         (do (read-all) (.write out buf) (.flush out)))
       (when (not= greeting (String. buf "UTF-8"))
         (throw (ex-info "tls-peer: greeting mismatch" {:got (String. buf "UTF-8")}))))
     :cljs
     (js/Promise.
      (fn [resolve reject]
        (let [seen (atom "")]
          (.on socket "data"
               (fn [chunk]
                 (swap! seen str (.toString chunk "utf8"))
                 (when (>= (count @seen) (count greeting))
                   (if (= greeting (subs @seen 0 (count greeting)))
                     (do (when (= :dial role) (.write socket greeting))
                         (resolve true))
                     (reject (js/Error. (str "tls-peer: greeting mismatch: " @seen)))))))
          (.on socket "error" reject)
          (when (= :serve role) (.write socket greeting)))))))

(defn- report [peer expect]
  (let [got (b/hex (:node-id peer))]
    (when (and expect (not= got expect))
      (println (str "FAIL peer id " got ", expected " expect))
      #?(:clj (System/exit 1) :cljs (js/process.exit 1)))
    (println (str "ok   handshake complete, peer " got))
    (println (str "peer " got))))

(defn serve [dir port expect]
  (let [identity (load-identity dir)
        done (fn [{:keys [socket peer]}]
               (report peer expect)
               #?(:clj (do (exchange! socket :serve)
                           (println "ok   application data flowed both ways")
                           (System/exit 0))
                  :cljs (-> (exchange! socket :serve)
                            (.then (fn [_]
                                     (println "ok   application data flowed both ways")
                                     (js/process.exit 0)))
                            (.catch (fn [e] (println (str "FAIL " (.-message e)))
                                      (js/process.exit 1))))))
        refused (fn [r] (println (str "FAIL refused: " (pr-str r)))
                  #?(:clj (System/exit 1) :cljs (js/process.exit 1)))]
    #?(:clj
       (let [l (htls/listen {:port port :identity identity :verify-opts {}
                             :on-connection done :on-refused refused})]
         (println (str "listening " (:port l)))
         (flush)
         ((:accept l)))
       :cljs
       (let [{:keys [server]} (htls/listen {:port port :identity identity
                                            :verify-opts {}
                                            :on-connection done
                                            :on-refused refused})]
         (.on server "listening"
              #(println (str "listening " (.-port (.address server)))))))))

(defn dial [dir addr expect]
  (let [identity (load-identity dir)
        [host port] (str/split addr #":")
        opts {:host host :port #?(:clj (parse-long port) :cljs (js/parseInt port 10))
              :identity identity
              :verify-opts (cond-> {} expect (assoc :expected-node-id (unhex expect)))}]
    #?(:clj
       (let [c (htls/connect opts)]
         (report (:peer c) expect)
         (exchange! (:socket c) :dial)
         (println "ok   application data flowed both ways")
         (htls/close! c))
       :cljs
       (-> (htls/connect opts)
           (.then (fn [c]
                    (report (:peer c) expect)
                    (-> (exchange! (:socket c) :dial)
                        (.then (fn [_]
                                 (println "ok   application data flowed both ways")
                                 ;; `end` rather than `destroy`: a half-close
                                 ;; lets the peer finish reading what was just
                                 ;; written, where destroy discards it
                                 (.end (:socket c))
                                 (js/process.exit 0))))))
           (.catch (fn [e]
                     (println (str "FAIL " (or (some-> e .-message) (str e))))
                     (js/process.exit 1)))))))

(defn- report-call [result rpc-name]
  (cond
    (:message result)
    (do (println (str "response " (drpc/utf8-string (:message result))))
        #?(:clj (System/exit 0) :cljs (js/process.exit 0)))

    (:error result)
    (do (println (str "FAIL error " (get-in result [:error :code])
                      " " (get-in result [:error :message])))
        #?(:clj (System/exit 1) :cljs (js/process.exit 1)))

    :else
    (do (println (str "FAIL " rpc-name " closed with no answer"))
        #?(:clj (System/exit 1) :cljs (js/process.exit 1)))))

(defn call
  "Dial over TLS, verify the peer, then make one DRPC call on that connection.

  The whole stack in one command: mutual TLS with Storj's rules, the node id
  checked against what was asked for, and a unary call on the socket that came
  out of it."
  [dir addr expect rpc-name payload]
  (let [identity (load-identity dir)
        [host port] (str/split addr #":")
        opts {:host host :port #?(:clj (parse-long port) :cljs (js/parseInt port 10))
              :identity identity
              :verify-opts (cond-> {} expect (assoc :expected-node-id (unhex expect)))}
        call-opts {:rpc rpc-name :request (drpc/ascii-bytes payload)}]
    #?(:clj
       (let [c (htls/connect opts)]
         (report (:peer c) expect)
         (report-call (rpc/call (:socket c) call-opts) rpc-name))
       :cljs
       (-> (htls/connect opts)
           (.then (fn [c]
                    (report (:peer c) expect)
                    (-> (rpc/call (:socket c) call-opts)
                        (.then #(report-call % rpc-name)))))
           (.catch (fn [e]
                     (println (str "FAIL " (or (some-> e .-message) (str e))))
                     (js/process.exit 1)))))))

(defn run [[mode dir arg expect rpc-name payload]]
  (case mode
    "serve" (serve dir #?(:clj (parse-long (or arg "0")) :cljs (js/parseInt (or arg "0") 10)) expect)
    "dial"  (dial dir arg expect)
    "call"  (call dir arg expect rpc-name payload)
    (do (println (str "usage: serve <dir> <port> | dial <dir> <host:port> [expect-hex]"
                      " | call <dir> <host:port> <expect-hex> <rpc> <payload>"))
        #?(:clj (System/exit 1) :cljs (js/process.exit 1)))))

#?(:clj (defn -main [& args] (run args)))
#?(:cljs (run (vec *command-line-args*)))
