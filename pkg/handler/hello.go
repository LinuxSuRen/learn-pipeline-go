package handler

import (
	"fmt"
	"html"
	"log"
	"net/http"

	"github.com/devopsws/learn-pipeline-go/pkg/oauth"
	"github.com/go-session/session"
)

type HelloWorld struct {
	Log *log.Logger
}

func (h *HelloWorld) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var name string
	if obj, ok := store.Get("userinfo"); ok && obj != nil {
		fmt.Println("user", obj)
		userInfo := obj.(*oauth.UserInfo)
		if userInfo != nil {
			name = userInfo.PreferredUsername
		}
	}

	fmt.Fprintf(w, "Hello %s, %q\n", name, html.EscapeString(r.URL.Path))
}
