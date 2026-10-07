package secret

import "testing"

func TestHash(t *testing.T) {
	Iterations = 2000
	h, err := Hash("correct horse battery")
	if err != nil || !Verify("correct horse battery", h) || Verify("correct horse batterY", h) || Verify("x", "nonsense") {
		t.Fatal("hash")
	}
	h2, _ := Hash("correct horse battery")
	if h == h2 {
		t.Fatal("salted")
	}
	if CheckPolicy("short", "") == nil || CheckPolicy("somchai-1234567", "somchai") == nil || CheckPolicy("long enough pw", "bob") != nil {
		t.Fatal("policy")
	}
	if len(Token(32)) != 43 || Token(16) == Token(16) {
		t.Fatal("token")
	}
}
