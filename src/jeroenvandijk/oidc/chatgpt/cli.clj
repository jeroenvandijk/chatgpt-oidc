(ns jeroenvandijk.oidc.chatgpt.cli
  (:require
   [babashka.cli :as cli]
   [jeroenvandijk.oidc.chatgpt.api :as api]))

(defn login
  "Sign in with ChatGPT using OIDC + PKCE"
  {:org.babashka/cli {:spec {:scope {:desc "The scope string for the request tokens"
                                     :coerce :string
                                     :default api/requested-scope-default}}}}
  [opts]
  (api/login! opts)
  nil)

(defn logout 
  "Revoke refresh token and clear saved token credentials"
  [& _]
  (api/logout!))

(defn refresh
  "Refresh the saved token set"
  [& _]
  (api/refresh!) 
  (api/eprintln "Token refreshed."))

(defn status
  "Show non-secret session metadata"
  [& _]
  (api/status!))

(def export-token-example 
  (str "  export ACCESS_TOKEN=$(" api/program-name " token)"))

(defn token 
  "Print a fresh access token to stdout"
  {:org.babashka/cli {:epilog ["Example"
                               export-token-example]}}
  [& _]
  (println (api/current-token!)))

(def tree {"login" {:exec-fn `login}
           "token" {:exec-fn `token}
           "refresh" {:exec-fn `refresh}
           "status" {:exec-fn `status}
           "logout" {:exec-fn `logout}})

(defn resolve-tree [tree]
  (clojure.walk/postwalk (fn [x]
                           (if-let [sym (:exec-fn x)]
                             (let [v (resolve sym)]
                               (merge {:exec-fn v} (:org.babashka/cli (meta sym))))
                             x))
                         tree))

(defn -main [& args]
  (cli/dispatch {:doc "CLI to manage OpenAI ChatGpt OIDC tokens"
                 :epilog ["Examples"
                          "  # initial login"
                          (str "  " api/program-name " login")
                          ""
                          "  # retrieve token"
                          export-token-example
                          ""]
                 :cmd (resolve-tree tree)}
                args
                {:prog api/program-name
                 :help true}))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
