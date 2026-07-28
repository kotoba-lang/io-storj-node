#!/usr/bin/env nbb
;; Run the suite on the ClojureScript side.
;;
;; Not a formality. This library reads 64-bit protobuf varints and 32-byte
;; identifiers, and JavaScript disagrees with the JVM about both: bitwise
;; operators truncate to int32, and a double stops representing integers
;; exactly past 2^53. It also reaches SHA-256 through a completely different
;; implementation here (`@noble/hashes` rather than `MessageDigest`), so the
;; checksum on every node ID is computed by different code than the JVM job
;; exercised.
;;
;;   nbb --classpath "$(clojure -A:cljs -Spath)" scripts/verify-cljs.cljs
(ns verify-cljs
  (:require [clojure.test :as t]
            [storj.node.id-test]
            [storj.node.identity-test]
            [storj.node.orders-test]
            [storj.node.pb-test]
            [storj.node.piece-test]))

(defmethod t/report [:cljs.test/default :end-run-tests] [m]
  (println)
  (if (t/successful? m)
    (println "all checks passed on the ClojureScript path")
    (do (println "FAILED on the ClojureScript path")
        (js/process.exit 1))))

(t/run-tests 'storj.node.id-test
             'storj.node.identity-test
             'storj.node.orders-test
             'storj.node.pb-test
             'storj.node.piece-test)
