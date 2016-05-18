package main

import (
	"net/http"

	"github.com/flynn/flynn/Godeps/_workspace/src/github.com/docker/distribution/context"
	"github.com/flynn/flynn/Godeps/_workspace/src/github.com/docker/distribution/registry/auth"
	"github.com/flynn/flynn/pkg/httphelper"
)

func init() {
	auth.Register("flynn", auth.InitFunc(newAuth))
}

func newAuth(options map[string]interface{}) (auth.AccessController, error) {
	return &Auth{key: options["auth_key"].(string)}, nil
}

type Auth struct {
	key string
}

// Authorized implements the auth.AccessController interface and authorizes a
// request if it is either considered to be internal (e.g. image pulls using
// docker-receive.discoverd) or includes the correct basic auth key
func (a *Auth) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := context.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	if !httphelper.IsInternal(req) && !httphelper.IsAuthorized(req, []string{a.key}) {
		return nil, Challenge{}
	}

	return ctx, nil
}

type Challenge struct{}

func (Challenge) SetHeaders(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=docker-receive")
}

func (Challenge) Error() string {
	return "basic authentication failed"
}
