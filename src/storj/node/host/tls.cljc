(ns storj.node.host.tls
  "Sockets — the mechanism under `storj.node.tls`.

  This is the first namespace in the repo that is *only* plumbing. It decides
  nothing: which certificates are acceptable is `storj.node.tls/verify-peer`'s
  answer, and everything here does is arrange for that answer to be asked at
  the right moment and to be acted on.

  ## The two runtimes do not ask at the same moment

  On the JVM the check runs **inside the handshake**, as an
  `X509ExtendedTrustManager`, which is where Go runs it too
  (`VerifyPeerCertificate`). A refused peer never completes a handshake.

  On Node there is no equivalent hook that fires without a certificate
  authority to check against, and Storj has none by construction. So the check
  runs on `secureConnect`/`secureConnection`, and a refused peer has completed
  a handshake before being disconnected — **before any application byte is
  written or read**, but after. That difference is real and is stated here
  rather than papered over: it means a refused peer on Node learns that this
  process exists and speaks TLS, which on the JVM it does not.

  ## What is missing

  DRPC is framed by `kotoba-lang/drpc` and is not wired in here; this hands
  back a connected, verified socket and stops. Nothing in this repo has
  spoken to a real satellite."
  (:require [storj.node.bytes :as b]
            [storj.node.host.keys :as hk]
            [storj.node.host.verify :as v]
            [storj.node.identity :as ident]
            [storj.node.tls :as tls]
            #?(:cljs ["node:tls" :as node-tls]))
  #?(:clj (:import (java.io ByteArrayInputStream)
                   (java.net InetSocketAddress)
                   (java.security KeyStore)
                   (java.security.cert CertificateFactory X509Certificate)
                   (javax.net.ssl KeyManagerFactory SSLContext SSLSocket
                                  X509ExtendedTrustManager))))

(def protocol
  "`tls.VersionTLS12` as each runtime spells it."
  #?(:clj "TLSv1.2" :cljs "TLSv1.2"))

(defn- fail [msg data]
  (throw (ex-info (str "storj.node.host.tls: " msg) data)))

;; ── the identity, in the form each runtime's TLS stack wants ────────────────

#?(:clj
   (defn- x509 [der]
     (.generateCertificate (CertificateFactory/getInstance "X.509")
                           (ByteArrayInputStream. (b/->native (vec der))))))

#?(:clj
   (defn- key-managers
     "A KeyManagerFactory holding the identity, via an in-memory keystore.

      The keystore password is empty and never leaves this function: it exists
      because `KeyStore.setKeyEntry` requires one, not because anything is
      being protected."
     [{:keys [chain private-key]}]
     (let [pw (char-array 0)
           ks (doto (KeyStore/getInstance "PKCS12")
                (.load nil pw)
                (.setKeyEntry "identity" private-key pw
                              (into-array X509Certificate (map x509 chain))))]
       (.getKeyManagers (doto (KeyManagerFactory/getInstance
                               (KeyManagerFactory/getDefaultAlgorithm))
                          (.init ks pw))))))

#?(:clj
   (defn- trust-manager
     "An `X509ExtendedTrustManager` that answers with `verify-peer`.

      Both the client and server callbacks route to the same check, because
      Storj asks the same question in both directions — the only difference is
      whether a whitelist is supplied, and that is the caller's to decide."
     [verify-opts on-peer]
     (let [check (fn [^"[Ljava.security.cert.X509Certificate;" chain]
                   (let [ders   (mapv #(b/->ints (.getEncoded ^X509Certificate %)) chain)
                         result (tls/verify-peer ders verify-opts)]
                     (when on-peer (on-peer result))
                     (when-not (:ok? result)
                       (fail "peer certificate refused" {:reasons (:reasons result)}))))]
       (proxy [X509ExtendedTrustManager] []
         (getAcceptedIssuers [] (into-array X509Certificate []))
         (checkClientTrusted
           ([chain _auth-type] (check chain))
           ([chain _auth-type _socket-or-engine] (check chain)))
         (checkServerTrusted
           ([chain _auth-type] (check chain))
           ([chain _auth-type _socket-or-engine] (check chain)))))))

#?(:clj
   (defn ssl-context
     "An `SSLContext` carrying the identity and the peer rules."
     [identity verify-opts on-peer]
     (doto (SSLContext/getInstance protocol)
       (.init (key-managers identity)
              (into-array javax.net.ssl.TrustManager [(trust-manager verify-opts on-peer)])
              nil))))

(defn pem-of
  "An identity as the PEM text a TLS stack takes.

  Public and not reader-conditional even though only the Node path uses it
  internally: both halves are portable, and hiding a portable function inside
  a platform branch is how a second copy gets written for the other one."
  [identity]
  {:cert (ident/chain-pem (:chain identity))
   :key  (ident/private-key-pem (hk/export-private-key (:private-key identity)))})

#?(:cljs
   (defn- peer-chain
     "The peer's certificates as DER, leaf first.

      Node hands back a linked structure rather than a list, and the last
      certificate points at itself — following that link forever is the
      obvious loop and the wrong one."
     [socket]
     (loop [cert (.getPeerCertificate socket true), out []]
       (if (or (nil? cert) (nil? (.-raw cert)))
         out
         (let [out'   (conj out (b/->ints (.-raw cert)))
               issuer (.-issuerCertificate cert)]
           (if (or (nil? issuer) (identical? issuer cert))
             out'
             (recur issuer out')))))))

;; ── connecting ──────────────────────────────────────────────────────────────

(defn connect
  "Dial `host:port` as a Storj peer and verify who answered.

  `identity` is `{:chain [leaf-der ca-der] :private-key <host key object>}`.
  `verify-opts` goes to `storj.node.tls/verify-peer` — pass
  `:expected-node-id` when the node being dialled is known, and
  `:whitelist (storj.node.tls/whitelist-certificates)` when it is a satellite.

  Returns `{:socket ... :peer {...}}` where `:peer` is the verification
  result, so the caller can read the node id it actually reached. On the JVM
  the handshake is forced before returning, so a refused peer surfaces here
  rather than on the first write.

  On cljs this returns a promise, because a Node socket has no synchronous
  handshake."
  [{:keys [host port identity verify-opts timeout-ms] :or {timeout-ms 20000}}]
  #?(:clj
     (let [seen (atom nil)
           ctx  (ssl-context identity (assoc verify-opts :verifier
                                             (or (:verifier verify-opts) v/verifier))
                             #(reset! seen %))
           ^SSLSocket sock (.createSocket (.getSocketFactory ctx))]
       (.setEnabledProtocols sock (into-array String [protocol]))
       (.connect sock (InetSocketAddress. ^String host (int port)) (int timeout-ms))
       (.setSoTimeout sock (int timeout-ms))
       ;; force the handshake now: without this a refused peer is discovered by
       ;; whichever later read or write happens to trigger it
       (.startHandshake sock)
       {:socket sock :peer @seen})

     :cljs
     (js/Promise.
      (fn [resolve reject]
        (let [{:keys [cert key]} (pem-of identity)
              opts (clj->js {:host host :port port :cert cert :key key
                             :rejectUnauthorized false
                             :minVersion protocol})
              sock (.connect node-tls opts)]
          (.setTimeout sock timeout-ms)
          (.on sock "error" reject)
          (.on sock "timeout" #(do (.destroy sock) (reject (js/Error. "tls: timeout"))))
          (.on sock "secureConnect"
               (fn []
                 (let [result (tls/verify-peer
                               (peer-chain sock)
                               (assoc verify-opts :verifier
                                      (or (:verifier verify-opts) v/verifier)))]
                   (if (:ok? result)
                     (resolve {:socket sock :peer result})
                     (do (.destroy sock)
                         (reject (try (fail "peer certificate refused"
                                            {:reasons (:reasons result)})
                                      (catch :default e e)))))))))))))

(defn listen
  "Accept Storj peers on `port`, calling `on-connection` with
  `{:socket ... :peer {...}}` once a peer has been verified.

  A peer that fails verification is disconnected and `on-connection` is not
  called; `on-refused`, if given, is called with the result instead."
  [{:keys [port identity verify-opts on-connection on-refused]}]
  #?(:clj
     (let [ctx (ssl-context identity (assoc verify-opts :verifier
                                            (or (:verifier verify-opts) v/verifier))
                            nil)
           server (.createServerSocket (.getServerSocketFactory ctx) (int port))]
       (.setNeedClientAuth ^javax.net.ssl.SSLServerSocket server true)
       (.setEnabledProtocols ^javax.net.ssl.SSLServerSocket server
                             (into-array String [protocol]))
       {:server server
        :port (.getLocalPort server)
        :accept (fn []
                  (let [^SSLSocket s (.accept server)]
                    (try
                      (.startHandshake s)
                      ;; the trust manager already ran; re-reading the chain
                      ;; here is how the caller learns which node it was
                      (let [ders (mapv #(b/->ints (.getEncoded ^X509Certificate %))
                                       (.getPeerCertificates (.getSession s)))
                            result (tls/verify-peer ders
                                                    (assoc verify-opts :verifier
                                                           (or (:verifier verify-opts) v/verifier)))]
                        (on-connection {:socket s :peer result}))
                      (catch Exception e
                        (.close s)
                        (when on-refused (on-refused e))))))})

     :cljs
     (let [{:keys [cert key]} (pem-of identity)
           server (.createServer node-tls
                                 (clj->js {:cert cert :key key
                                           :requestCert true
                                           :rejectUnauthorized false
                                           :minVersion protocol})
                                 (fn [sock]
                                   (let [result (tls/verify-peer
                                                 (peer-chain sock)
                                                 (assoc verify-opts :verifier
                                                        (or (:verifier verify-opts) v/verifier)))]
                                     (if (:ok? result)
                                       (on-connection {:socket sock :peer result})
                                       (do (.destroy sock)
                                           (when on-refused (on-refused result)))))))]
       (.listen server port)
       {:server server})))

(defn close! [{:keys [socket server]}]
  #?(:clj  (do (when socket (.close socket)) (when server (.close server)))
     :cljs (do (when socket (.destroy socket)) (when server (.close server)))))
