(ns mint-identity
  "Mint an identity with this runtime's crypto and write it where the Go
  verifier can read it.

  One file for both runtimes, because the point of running it twice is that
  the *library* is the same and the crypto underneath it is not — a JVM
  `KeyPairGenerator` and Node's OpenSSL bindings, producing certificates that
  Storj then has to accept from either.

      clojure -M:mint testdata/minted.edn 16
      nbb --classpath \"$(clojure -A:cljs -Spath)\" scripts/mint_identity.cljc \\
        testdata/minted-cljs.edn 16
      cd testdata && go run verify_minted.go -in minted.edn

  Nothing in the test suite depends on the output: it is an artifact for the
  reference implementation to judge, and CI regenerates it every run rather
  than checking one in. A fixed identity would only ever prove that one
  identity was well formed."
  (:require [storj.node.bytes :as b]
            [storj.node.host.keys :as hk]
            [storj.node.mint :as mint]
            #?(:cljs ["node:fs" :as fs])))

(defn run [path difficulty]
  (let [m (mint/mint hk/key-material {:difficulty difficulty})
        edn (str "{;; minted by scripts/mint_identity.cljc — not a fixture\n"
                 " :ca-der \"" (b/hex (get-in m [:ca :der])) "\"\n"
                 " :leaf-der \"" (b/hex (get-in m [:leaf :der])) "\"\n"
                 " :node-id \"" (b/hex (:node-id m)) "\"\n"
                 " :difficulty " (:difficulty m) "\n"
                 " :attempts " (:attempts m) "\n"
                 " :version 0}\n")]
    #?(:clj (spit path edn) :cljs (fs/writeFileSync path edn))
    (println "minted" (b/hex (:node-id m))
             "difficulty" (:difficulty m)
             "after" (:attempts m) "attempts →" path)))

#?(:clj
   (defn -main [& [path difficulty]]
     (run (or path "testdata/minted.edn")
          (if difficulty (parse-long difficulty) 16))))

#?(:cljs
   ;; `*command-line-args*` rather than `process.argv`: nbb's own flags sit in
   ;; argv ahead of the script, so dropping a fixed number of entries reads
   ;; `--classpath` as the output path and the classpath itself as the
   ;; difficulty, which then never matches and looks like bad luck.
   (let [[path difficulty] *command-line-args*]
     (run (or path "testdata/minted-cljs.edn")
          (if difficulty (js/parseInt difficulty 10) 16))))
