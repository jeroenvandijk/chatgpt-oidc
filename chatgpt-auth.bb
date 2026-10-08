#!/usr/bin/env bb

(ns chatgpt-auth
  (:require [babashka.http-client :as http]
            [babashka.process :as process]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import (java.io BufferedReader ByteArrayOutputStream InputStreamReader)
           (java.net InetAddress ServerSocket URI URLDecoder URLEncoder)
           (java.nio.file Files)
           (java.nio.file.attribute PosixFilePermissions)
           (java.security KeyFactory MessageDigest SecureRandom Signature)
           (java.security.spec X509EncodedKeySpec)
           (java.time Instant)
           (java.util Base64 UUID)))

(def ^:private app-name
  (or (System/getenv "CHATGPT_AGENT_NAME") "Babashka ChatGPT CLI"))
(def ^:private issuer "https://auth.openai.com")
(def ^:private discovery-url "https://auth.openai.com/.well-known/openid-configuration")
(def ^:private resource "https://api.openai.com/v1")
(def ^:private requested-scope
  "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct")
(def ^:private callback-path "/auth/callback")
(def ^:private callback-timeout-ms (* 10 60 1000))
(def ^:private refresh-skew-seconds 120)
(def ^:private rng (SecureRandom.))

(defn- eprintln [& xs]
  (binding [*out* *err*]
    (apply println xs)))

(defn- fail! [message]
  (throw (ex-info message {})))

(defn- config-dir []
  (io/file (System/getProperty "user.home") ".config" "chatgpt-bb-oidc"))

(defn- auth-file []
  (io/file (config-dir) "auth.edn"))

(defn- host-file []
  (io/file (config-dir) "host.edn"))

(defn- chmod-600! [f]
  (try
    (Files/setPosixFilePermissions (.toPath (io/file f))
                                   (PosixFilePermissions/fromString "rw-------"))
    (catch Exception _
      ;; Non-POSIX filesystems (notably Windows) do not support this API.
      nil)))

(defn- save-auth! [m]
  (.mkdirs (config-dir))
  (let [f (auth-file)
        tmp (io/file (config-dir) (str ".auth." (UUID/randomUUID) ".tmp"))]
    (spit tmp (str (pr-str m) "\n"))
    (chmod-600! tmp)
    ;; Rename in the same directory. Java's renameTo is atomic on common local
    ;; filesystems, though the platform does not guarantee it everywhere.
    (when-not (.renameTo tmp f)
      (spit f (slurp tmp))
      (.delete tmp))
    (chmod-600! f))
  m)

(defn- load-auth []
  (let [f (auth-file)]
    (when (.exists f)
      (edn/read-string (slurp f)))))

(defn- ensure-host-id! []
  (.mkdirs (config-dir))
  (let [f (host-file)]
    (if (.exists f)
      (:ext-agent-host-id (edn/read-string (slurp f)))
      (let [host-id (str "urn:uuid:" (UUID/randomUUID))]
        (spit f (str (pr-str {:ext-agent-host-id host-id}) "\n"))
        (chmod-600! f)
        host-id))))

(defn- bytes->b64url [bs]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bs))

(defn- b64url->bytes [s]
  (.decode (Base64/getUrlDecoder) s))

(defn- random-token [n]
  (let [bs (byte-array n)]
    (.nextBytes rng bs)
    (bytes->b64url bs)))

(defn- sha256 [s]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.digest md (.getBytes (str s) "UTF-8"))))

(defn- pkce-challenge [verifier]
  (bytes->b64url (sha256 verifier)))

(defn- url-encode [x]
  (URLEncoder/encode (str x) "UTF-8"))

(defn- url-decode [x]
  (URLDecoder/decode (str x) "UTF-8"))

(defn- build-url [base params]
  (str base "?"
       (->> params
            (remove (comp nil? val))
            (map (fn [[k v]]
                   (str (url-encode (name k)) "=" (url-encode v))))
            (str/join "&"))))

(defn- parse-query [raw]
  (if (str/blank? raw)
    {}
    (into {}
          (map (fn [part]
                 (let [[k v] (str/split part #"=" 2)]
                   [(url-decode k) (url-decode (or v ""))])))
          (str/split raw #"&"))))

(defn- get-json! [url]
  (let [resp (http/get url {:headers {:accept "application/json"}
                            :throw false
                            :timeout 30000})]
    (when-not (= 200 (:status resp))
      (fail! (str "GET " url " failed with HTTP " (:status resp))))
    (json/parse-string (:body resp) true)))

(defn- post-form-json! [url form]
  (let [resp (http/post url {:headers {:accept "application/json"}
                             :form-params form
                             :throw false
                             :timeout 30000})
        parsed (try
                 (json/parse-string (:body resp) true)
                 (catch Exception _ {:raw_body (:body resp)}))]
    (when-not (= 200 (:status resp))
      (let [err (or (:error_description parsed)
                    (:error parsed)
                    (:raw_body parsed)
                    "unknown OAuth error")]
        (fail! (str "OAuth token request failed (HTTP " (:status resp) "): " err))))
    parsed))

(defn- discovery! []
  (let [d (get-json! discovery-url)]
    (when-not (= issuer (:issuer d))
      (fail! "OIDC discovery returned an unexpected issuer"))
    (when-not (some #{"RS256"} (:id_token_signing_alg_values_supported d))
      (fail! "OIDC discovery does not advertise RS256 ID-token signing"))
    d))

;; --- Minimal DER encoder, used to turn an RSA JWK (n/e) into X.509 SPKI. ---

(defn- concat-bytes [& arrays]
  (let [out (ByteArrayOutputStream.)]
    (doseq [a arrays]
      (.write out a 0 (alength a)))
    (.toByteArray out)))

(defn- byte-array* [xs]
  (byte-array (map unchecked-byte xs)))

(defn- der-length [n]
  (if (< n 128)
    (byte-array* [n])
    (let [parts (loop [x n acc ()]
                  (if (zero? x)
                    acc
                    (recur (unsigned-bit-shift-right x 8)
                           (conj acc (bit-and x 0xff)))))]
      (byte-array* (cons (+ 0x80 (count parts)) parts)))))

(defn- der [tag content]
  (concat-bytes (byte-array* [tag])
                (der-length (alength content))
                content))

(defn- trim-leading-zeroes [bs]
  (loop [i 0]
    (if (and (< i (dec (alength bs)))
             (zero? (bit-and 0xff (aget bs i))))
      (recur (inc i))
      (java.util.Arrays/copyOfRange bs i (alength bs)))))

(defn- der-positive-integer [unsigned-bytes]
  (let [v (trim-leading-zeroes unsigned-bytes)
        needs-zero? (>= (bit-and 0xff (aget v 0)) 128)
        content (if needs-zero?
                  (concat-bytes (byte-array* [0]) v)
                  v)]
    (der 0x02 content)))

(def ^:private rsa-algorithm-id
  ;; SEQUENCE { OID rsaEncryption 1.2.840.113549.1.1.1, NULL }
  (byte-array* [0x30 0x0d 0x06 0x09 0x2a 0x86 0x48 0x86 0xf7 0x0d
                0x01 0x01 0x01 0x05 0x00]))

(defn- jwk->public-key [{:keys [kty n e]}]
  (when-not (= "RSA" kty)
    (fail! (str "Unsupported JWKS key type: " kty)))
  (let [rsa-public-key (der 0x30
                            (concat-bytes
                             (der-positive-integer (b64url->bytes n))
                             (der-positive-integer (b64url->bytes e))))
        bit-string (der 0x03 (concat-bytes (byte-array* [0]) rsa-public-key))
        spki (der 0x30 (concat-bytes rsa-algorithm-id bit-string))
        key-factory (KeyFactory/getInstance "RSA")]
    (.generatePublic key-factory (X509EncodedKeySpec. spki))))

(defn- jwt-parts [jwt]
  (let [parts (str/split jwt #"\." -1)]
    (when-not (= 3 (count parts))
      (fail! "Malformed ID token"))
    (let [[h p s] parts]
      {:header-segment h
       :payload-segment p
       :signature-segment s
       :header (json/parse-string (String. (b64url->bytes h) "UTF-8") true)
       :claims (json/parse-string (String. (b64url->bytes p) "UTF-8") true)})))

(defn- audience-matches? [aud expected]
  (cond
    (string? aud) (= aud expected)
    (sequential? aud) (boolean (some #{expected} aud))
    :else false))

(defn- validate-id-token! [id-token client-id expected-nonce jwks-uri]
  (let [{:keys [header-segment payload-segment signature-segment header claims]}
        (jwt-parts id-token)
        {:keys [alg kid]} header]
    (when-not (= "RS256" alg)
      (fail! (str "Unexpected ID-token alg: " alg)))
    (when (str/blank? kid)
      (fail! "ID token is missing kid"))
    (let [jwks (get-json! jwks-uri)
          jwk (some #(when (= kid (:kid %)) %) (:keys jwks))]
      (when-not jwk
        (fail! "ID-token signing key was not found in OpenAI JWKS"))
      (let [signature (Signature/getInstance "SHA256withRSA")
            signing-input (.getBytes (str header-segment "." payload-segment) "UTF-8")]
        (.initVerify signature (jwk->public-key jwk))
        (.update signature signing-input)
        (when-not (.verify signature (b64url->bytes signature-segment))
          (fail! "ID-token signature verification failed"))))
    (let [now (.getEpochSecond (Instant/now))]
      (when-not (= issuer (:iss claims))
        (fail! "ID token has an unexpected issuer"))
      (when-not (audience-matches? (:aud claims) client-id)
        (fail! "ID token has an unexpected audience"))
      (when (or (nil? (:exp claims)) (<= (long (:exp claims)) (- now 60)))
        (fail! "ID token is expired"))
      (when-not (= expected-nonce (:nonce claims))
        (fail! "ID token nonce did not match this authorization attempt"))
      (when (str/blank? (:sub claims))
        (fail! "ID token is missing sub")))
    claims))

(defn- start-loopback! []
  (let [server (ServerSocket. 0 50 (InetAddress/getByName "127.0.0.1"))]
    (.setSoTimeout server callback-timeout-ms)
    {:server server
     :redirect-uri (str "http://127.0.0.1:" (.getLocalPort server) callback-path)}))

(defn- read-request-line! [reader]
  (let [line (.readLine reader)]
    (loop []
      (let [h (.readLine reader)]
        (when (and h (not (str/blank? h)))
          (recur))))
    line))

(defn- browser-response! [socket status body]
  (let [payload (.getBytes body "UTF-8")
        reason (if (= status 200) "OK" "Bad Request")
        headers (str "HTTP/1.1 " status " " reason "\r\n"
                     "Content-Type: text/html; charset=utf-8\r\n"
                     "Cache-Control: no-store\r\n"
                     "Content-Length: " (alength payload) "\r\n"
                     "Connection: close\r\n\r\n")
        out (.getOutputStream socket)]
    (.write out (.getBytes headers "UTF-8"))
    (.write out payload)
    (.flush out)))

(defn- await-callback! [server]
  (with-open [socket (.accept server)
              reader (BufferedReader. (InputStreamReader. (.getInputStream socket) "UTF-8"))]
    (let [request-line (read-request-line! reader)
          [_ target _] (str/split (or request-line "") #" " 3)
          uri (when target
                (URI. (if (str/starts-with? target "http")
                        target
                        (str "http://127.0.0.1" target))))]
      (if (or (nil? uri) (not= callback-path (.getPath uri)))
        (do
          (browser-response! socket 400 "<h1>Invalid callback</h1>")
          (fail! "Received an unexpected loopback callback"))
        (let [params (parse-query (.getRawQuery uri))]
          (browser-response! socket 200
                             "<html><body><h2>Authorization complete</h2><p>You can close this window and return to the terminal.</p></body></html>")
          params)))))

(defn- launch-browser! [url]
  (eprintln "Open this URL if your browser does not launch automatically:")
  (eprintln url)
  (try
    (let [os (-> (System/getProperty "os.name") str/lower-case)]
      (cond
        (str/includes? os "mac")
        (process/process ["open" url] {:out :string :err :string})

        (str/includes? os "win")
        (process/process ["cmd" "/c" "start" "" url] {:out :string :err :string})

        :else
        (process/process ["xdg-open" url] {:out :string :err :string})))
    (catch Exception _
      nil)))

(defn- granted-scopes [token-response]
  (set (remove str/blank? (str/split (or (:scope token-response) "") #"\s+"))))

(defn- login! []
  (let [host-id (ensure-host-id!)
        existing (or (load-auth) {})
        discovery (discovery!)
        new-registration? (nil? (:client-id existing))
        request-client-id (if new-registration?
                            "dynamic_agent_client"
                            (:client-id existing))
        state (random-token 32)
        nonce (random-token 32)
        verifier (random-token 64)
        challenge (pkce-challenge verifier)
        {:keys [server redirect-uri]} (start-loopback!)]
    (try
      (let [authorize-url
            (build-url (:authorization_endpoint discovery)
                       (cond-> {:client_id request-client-id
                                :ext_agent_host_id host-id
                                :response_type "code"
                                :redirect_uri redirect-uri
                                :scope requested-scope
                                :resource resource
                                :state state
                                :nonce nonce
                                :code_challenge_method "S256"
                                :code_challenge challenge}
                         new-registration?
                         (assoc :agent_name_hint app-name)

                         (and (not new-registration?) (:email existing))
                         (assoc :login_hint (:email existing))))]
        (launch-browser! authorize-url)
        (let [callback (await-callback! server)]
          (when-not (= state (get callback "state"))
            (fail! "OAuth state did not match this authorization attempt"))
          (when-let [oauth-error (get callback "error")]
            (fail! (str "Authorization failed: " oauth-error
                        (when-let [d (get callback "error_description")]
                          (str " — " d)))))
          (let [code (get callback "code")
                callback-client-id (get callback "client_id")
                issued-client-id
                (if new-registration?
                  (or callback-client-id
                      (fail! "Initial registration callback did not include an issued client_id"))
                  (do
                    (when (and callback-client-id
                               (not= callback-client-id (:client-id existing)))
                      (fail! "Reauthorization returned a different client_id"))
                    (:client-id existing)))]
            (when (str/blank? code)
              (fail! "Authorization callback did not include a code"))
            ;; OpenAI recommends retaining a newly issued dynamic client ID before
            ;; code exchange, so an expired/invalid code can be retried without
            ;; creating another registration.
            (when new-registration?
              (save-auth! (assoc existing
                                 :client-id issued-client-id
                                 :ext-agent-host-id host-id)))
            (let [token-response
                  (post-form-json!
                   (:token_endpoint discovery)
                   {:grant_type "authorization_code"
                    :client_id issued-client-id
                    :code code
                    :code_verifier verifier
                    :redirect_uri redirect-uri
                    :resource resource})
                  id-token (:id_token token-response)]
              (when (str/blank? id-token)
                (fail! "Token endpoint did not return an ID token"))
              (let [claims (validate-id-token! id-token issued-client-id nonce (:jwks_uri discovery))
                    scopes (granted-scopes token-response)]
                (when (and (:subject existing)
                           (not= (:subject existing) (:sub claims)))
                  (fail! "Reauthorization returned a different ChatGPT account"))
                (when-not (contains? scopes "chatgpt.tokens.use.direct")
                  (fail! "Sign-in succeeded, but ChatGPT plan usage was not authorized"))
                (let [saved (save-auth!
                             {:email (:email claims)
                              :issuer (:iss claims)
                              :subject (:sub claims)
                              :client-id issued-client-id
                              :ext-agent-host-id host-id
                              :id-token id-token
                              :access-token (:access_token token-response)
                              :refresh-token (:refresh_token token-response)
                              :token-type (:token_type token-response)
                              :expires-in (:expires_in token-response)
                              :scope (:scope token-response)
                              :earliest-refresh-at (:earliest_refresh_at token-response)
                              :saved-at (.toString (Instant/now))})]
                  (eprintln "Signed in successfully. Credentials saved to" (.getPath (auth-file)))
                  (eprintln "Run: ./chatgpt-auth.bb token")
                  saved))))))
      (finally
        (.close server)))))

(defn- require-auth []
  (let [auth (load-auth)]
    (cond
      (nil? auth)
      (fail! "No saved credentials. Run `./chatgpt-auth.bb login` first.")

      (and (str/blank? (:access-token auth))
           (str/blank? (:refresh-token auth)))
      (fail! "Signed out. Run `./chatgpt-auth.bb login` to authorize again.")

      :else auth)))

(defn- access-token-expired-soon? [auth]
  (let [saved-at (:saved-at auth)
        expires-in (long (or (:expires-in auth) 0))]
    (or (nil? saved-at)
        (nil? (:access-token auth))
        (let [expires-at (+ (.getEpochSecond (Instant/parse saved-at)) expires-in)
              now (.getEpochSecond (Instant/now))]
          (<= expires-at (+ now refresh-skew-seconds))))))

(defn- refresh! []
  (let [auth (require-auth)
        discovery (discovery!)]
    (when (str/blank? (:refresh-token auth))
      (fail! "No refresh token is saved; run login again."))
    (let [token-response
          (post-form-json!
           (:token_endpoint discovery)
           {:grant_type "refresh_token"
            :client_id (:client-id auth)
            :refresh_token (:refresh-token auth)
            :resource resource})
          updated (-> auth
                      (assoc :access-token (:access_token token-response)
                             :refresh-token (or (:refresh_token token-response)
                                                (:refresh-token auth))
                             :token-type (or (:token_type token-response)
                                             (:token-type auth))
                             :expires-in (or (:expires_in token-response)
                                             (:expires-in auth))
                             :scope (or (:scope token-response)
                                        (:scope auth))
                             :earliest-refresh-at (:earliest_refresh_at token-response)
                             :saved-at (.toString (Instant/now)))
                      (cond-> (:id_token token-response)
                        (assoc :id-token (:id_token token-response))))]
      (save-auth! updated)
      updated)))

(defn- current-token! []
  (let [auth (require-auth)
        auth (if (access-token-expired-soon? auth)
               (refresh!)
               auth)]
    (when (str/blank? (:access-token auth))
      (fail! "No access token is available; run login again."))
    (:access-token auth)))

(defn- status! []
  (let [auth (load-auth)
        signed-in? (and auth
                        (or (not (str/blank? (:access-token auth)))
                            (not (str/blank? (:refresh-token auth)))))]
    (println (if signed-in? "signed in" "signed out"))
    (when auth
      (println "email:" (or (:email auth) "<not present>"))
      (println "client-id:" (or (:client-id auth) "<not registered yet>"))
      (println "host-id:" (if (.exists (host-file))
                             (:ext-agent-host-id (edn/read-string (slurp (host-file))))
                             (:ext-agent-host-id auth)))
      (when (and signed-in? (:saved-at auth) (:expires-in auth))
        (let [expires-at (.plusSeconds (Instant/parse (:saved-at auth))
                                       (long (:expires-in auth)))]
          (println "access-token-expires-at:" (.toString expires-at)))))))

(defn- revoke-refresh-token! [auth]
  (when-not (str/blank? (:refresh-token auth))
    (let [discovery (discovery!)
          endpoint (:revocation_endpoint discovery)]
      (when (str/blank? endpoint)
        (fail! "OIDC discovery did not advertise a revocation endpoint"))
      (let [resp (http/post endpoint
                            {:form-params {:token (:refresh-token auth)
                                           :token_type_hint "refresh_token"
                                           :client_id (:client-id auth)}
                             :throw false
                             :timeout 30000})]
        (when-not (= 200 (:status resp))
          (fail! (str "Refresh-token revocation failed with HTTP " (:status resp))))))))

(defn- logout! []
  (if-let [auth (load-auth)]
    (let [revoked?
          (try
            (revoke-refresh-token! auth)
            true
            (catch Exception e
              (eprintln "warning: remote refresh-token revocation could not be confirmed:"
                        (.getMessage e))
              false))
          registration (select-keys auth
                                    [:email :issuer :subject :client-id :ext-agent-host-id])]
      ;; Keep the non-secret registration mapping so a later login reuses the
      ;; issued oaiapp_ client ID, but remove all bearer/refresh/ID tokens.
      (save-auth! (assoc registration :signed-out true))
      (println (if revoked?
                 "Signed out. Refresh token revoked; registration mapping retained."
                 "Signed out locally; registration mapping retained. Remote revocation was not confirmed.")))
    (println "No local credentials found.")))

(defn- usage []
  (println "Usage: chatgpt-auth.bb <command>")
  (println)
  (println "Commands:")
  (println "  login    Sign in with ChatGPT using OIDC + PKCE")
  (println "  token    Print a fresh access token to stdout")
  (println "  refresh  Refresh the saved token set")
  (println "  status   Show non-secret session metadata")
  (println "  logout   Revoke refresh token and clear saved token credentials")
  (println)
  (println "Example:")
  (println "  export ACCESS_TOKEN=\"$(./chatgpt-auth.bb token)\""))

(defn -main [& args]
  (try
    (case (first args)
      "login" (do (login!) nil)
      "token" (println (current-token!))
      "refresh" (do (refresh!) (eprintln "Token refreshed."))
      "status" (status!)
      "logout" (logout!)
      (usage))
    (catch Exception e
      (eprintln "error:" (.getMessage e))
      (System/exit 1))))

(apply -main *command-line-args*)
