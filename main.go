package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/devopsws/learn-pipeline-go/pkg/handler"
	"github.com/devopsws/learn-pipeline-go/pkg/handler/auth"
	"github.com/devopsws/learn-pipeline-go/pkg/oauth"
	"github.com/go-session/session"
	"golang.org/x/oauth2"
)

const (
	authServerURL = "https://github.com/login"
)

var (
	config = oauth2.Config{
		ClientID:     "91daa19893d9194e3fd9",
		ClientSecret: "3f4f242430344f2c600534c006fda8ed5df71aa3",
		Scopes:       []string{"all", "read_user_info"},
		RedirectURL:  "http://localhost/oauth2/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + "/oauth/authorize",
			TokenURL: authServerURL + "/oauth/access_token",
		},
	}
	globalToken *oauth2.Token // Non-concurrent security
)

func main() {
	sm := http.NewServeMux()
	sm.Handle("/", &handler.HelloWorld{})
	sm.Handle("/version", &handler.Version{})

	authHandler := auth.NewAuth(config)
	sm.HandleFunc("/login", authHandler.LoginHandler)
	sm.HandleFunc("/auth", authHandler.AuthHandler)
	sm.HandleFunc("/token", authHandler.RequestCode)
	sm.HandleFunc("/oauth2/callback", authHandler.Callback)

	oauthServer := oauth.NewServer()
	sm.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get("ReturnUri"); ok {
			form = v.(url.Values)
		}
		r.Form = form

		store.Delete("ReturnUri")
		store.Save()

		err = oauthServer.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	sm.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		err := oauthServer.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	sm.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		if globalToken == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		globalToken.Expiry = time.Now()
		token, err := config.TokenSource(context.Background(), globalToken).Token()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		globalToken = token
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(token)
	})

	svr := http.Server{
		Addr:    ":8899",
		Handler: sm,
	}

	go func() {
		err := svr.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()

	sigChain := make(chan os.Signal)
	signal.Notify(sigChain, os.Interrupt)
	signal.Notify(sigChain, os.Kill)

	sig := <-sigChain
	fmt.Println("going to shutdown", sig)
	tc, _ := context.WithTimeout(context.Background(), 30*time.Second)

	if err := svr.Shutdown(tc); err != nil {
		log.Fatalf("cannot shutdown http server, %v\n", err)
	}
}

func genCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(s256[:])
}
