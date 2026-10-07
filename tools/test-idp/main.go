// Command test-idp is a minimal OpenID provider for heain-gateway's live test
// (TEST ONLY): it signs in whoever login_hint names, without asking.
//
//	test-idp -listen 127.0.0.1:18444 -client-id gw -client-secret s3cret
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/heainframework/heain-gateway/internal/oidc/fakeidp"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18444", "address (plain HTTP, loopback only)")
	id := flag.String("client-id", "gw", "the client id")
	secret := flag.String("client-secret", "", "the client secret")
	flag.Parse()
	p := fakeidp.New(*id, *secret)
	p.Issuer = "http://" + *listen
	log.Printf("test-idp: TEST ONLY provider at %s", p.Issuer)
	log.Fatal(http.ListenAndServe(*listen, p))
}
