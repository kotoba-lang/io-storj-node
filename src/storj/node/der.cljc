(ns storj.node.der
  "Just enough DER to read an X.509 certificate.

  Not a general ASN.1 library and not trying to be. A peer's certificate
  arrives as bytes and four things have to be got out of it — the public key,
  the signed body, the signature, and a couple of extensions — so this reads
  tag-length-value and nothing more. Values stay as bytes; nothing is
  interpreted here.

  ## Why parse at all rather than take it pre-parsed

  A host running TLS already has a parsed certificate, and this library could
  have asked for the pieces. But then the host is doing the part that decides:
  which bytes were signed, which key signed them, which extension said what.
  Those are the questions this library exists to answer, and handing them to
  every caller means every caller can answer them differently. Parsing here
  keeps the decisions in one place, and the seam becomes the one thing a host
  genuinely must own — `verify this signature`.

  ## Lengths

  Long-form lengths are bounded to four bytes, and indefinite-length encoding
  is refused outright. DER forbids indefinite length; accepting it would mean
  scanning for an end-of-contents marker, which is precisely the kind of
  attacker-steerable scan a certificate parser should not contain."
  (:require [clojure.string :as str]
            [storj.node.bytes :as b]))

(defn- fail [msg data]
  (throw (ex-info (str "storj.node.der: " msg) data)))

(def ^:private class-names
  {2r00 :universal 2r01 :application 2r10 :context 2r11 :private})

(defn read-tlv
  "Read one tag-length-value element at `offset`.

  Returns a map describing the element: its tag, whether it is constructed,
  the offsets of its contents, and `:der` — the element's own bytes including
  tag and length. That last field is what a caller needs when the bytes
  themselves are the thing being signed."
  [bs offset]
  (let [v (vec bs)
        n (count v)]
    (when (>= (inc offset) n)
      (fail "truncated element" {:offset offset}))
    (let [id       (nth v offset)
          tag-num  (bit-and id 2r00011111)
          _        (when (= tag-num 2r00011111)
                     (fail "high-tag-number form is not supported" {:offset offset}))
          len-byte (nth v (inc offset))
          [length header]
          (if (zero? (bit-and len-byte 0x80))
            [len-byte 2]
            (let [k (bit-and len-byte 0x7f)]
              (when (zero? k)
                (fail "indefinite length is not valid DER" {:offset offset}))
              (when (> k 4)
                (fail "length field too large" {:offset offset :bytes k}))
              (when (> (+ offset 2 k) n)
                (fail "truncated length" {:offset offset}))
              [(reduce (fn [acc i] (+ (* acc 256) (nth v (+ offset 2 i))))
                       0 (range k))
               (+ 2 k)]))
          from (+ offset header)
          to   (+ from length)]
      (when (> to n)
        (fail "element runs past the end of the input"
              {:offset offset :declared-length length :available (- n from)}))
      {:tag         tag-num
       :class       (class-names (bit-and (bit-shift-right id 6) 2r11))
       :constructed (pos? (bit-and id 2r00100000))
       :start       offset
       :contents    (subvec v from to)
       :der         (subvec v offset to)
       :end         to})))

(defn children
  "The elements directly inside a constructed element."
  [{:keys [constructed contents] :as element}]
  (when-not constructed
    (fail "not a constructed element" {:tag (:tag element)}))
  (loop [offset 0, out []]
    (if (>= offset (count contents))
      out
      (let [c (read-tlv contents offset)]
        (recur (:end c) (conj out c))))))

(defn parse
  "Read the single element a DER blob contains, refusing trailing bytes.

  Trailing bytes are refused rather than ignored because a certificate with
  something appended is not a certificate — and a parser that quietly ignores
  the tail lets two implementations disagree about what they just verified."
  [bs]
  (let [v (vec bs)
        e (read-tlv v 0)]
    (when (not= (:end e) (count v))
      (fail "trailing bytes after the top-level element"
            {:consumed (:end e) :total (count v)}))
    e))

;; ── the few types this needs to interpret ────────────────────────────────────

(def tags
  {:boolean 1 :integer 2 :bit-string 3 :octet-string 4 :null 5
   :oid 6 :utf8-string 12 :sequence 16 :set 17})

(defn tag? [element k]
  (and (= :universal (:class element)) (= (tags k) (:tag element))))

(defn bit-string-bytes
  "The bytes of a BIT STRING, dropping its leading unused-bit count.

  Refuses a nonzero count: every bit string a certificate carries here is a
  whole number of bytes, and a partial trailing byte would mean the signature
  is not what it appears to be."
  [element]
  (when-not (tag? element :bit-string)
    (fail "not a BIT STRING" {:tag (:tag element)}))
  (let [c (:contents element)]
    (when (empty? c)
      (fail "empty BIT STRING" {}))
    (when-not (zero? (first c))
      (fail "BIT STRING with unused bits" {:unused (first c)}))
    (subvec c 1)))

(defn oid
  "An OBJECT IDENTIFIER as its dotted string.

  The first byte packs two arcs. Values of 80 and above mean the first arc is
  2 — the joint-iso-itu-t branch Storj's private extensions live under — and
  the second is what is left after subtracting 80. Dividing by 40
  unconditionally, which reads as the obvious rule, mangles every OID in that
  branch: `2.999.2.1` would come out as `24.39.2.1`."
  [element]
  (when-not (tag? element :oid)
    (fail "not an OBJECT IDENTIFIER" {:tag (:tag element)}))
  (let [arcs (loop [bytes (:contents element), acc 0, out []]
               (if (empty? bytes)
                 out
                 (let [b (first bytes)
                       acc (+ (* acc 128) (bit-and b 0x7f))]
                   (if (pos? (bit-and b 0x80))
                     (recur (rest bytes) acc out)
                     (recur (rest bytes) 0 (conj out acc))))))
        [head & tail] arcs]
    (when (nil? head)
      (fail "empty OBJECT IDENTIFIER" {}))
    (let [[a b] (if (>= head 80) [2 (- head 80)] [(quot head 40) (rem head 40)])]
      (str/join "." (concat [a b] tail)))))

(defn integer-bytes
  "The contents of an INTEGER, unmodified — sign byte and all."
  [element]
  (when-not (tag? element :integer)
    (fail "not an INTEGER" {:tag (:tag element)}))
  (:contents element))

(defn hex
  "Hex of an element's own bytes, for identifying it in a message."
  [element]
  (b/hex (:der element)))
