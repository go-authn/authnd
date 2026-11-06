//go:build !nosql

package main

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// asReqCode sends an AS-REQ without pre-authentication for name over UDP and
// returns the KRB-ERROR code the realm answers. A person the realm holds with
// a password is KDC_ERR_PREAUTH_REQUIRED (25).
func asReqCode(t *testing.T, r *running, name string) int32 {
	t.Helper()
	c := krbconfig.New()
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{18}
	req, err := messages.NewASReqForTGT(testRealm, c, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.srv.KerberosPort())))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer from the realm: %v\n%s", err, r.out.String())
	}
	var e messages.KRBError
	if err := e.Unmarshal(buf[:n]); err != nil {
		t.Fatalf("the answer is not a KRB-ERROR: %v", err)
	}
	return e.ErrorCode
}

func realmOverSQL(t *testing.T, extra string) (*running, string, *fakeClock) {
	t.Helper()
	dir := t.TempDir()
	r, db, clk, _ := refreshing(t, fmt.Sprintf(`%s
kerberos {
  realm  = %q
  listen = "127.0.0.1:0"
  keytab = %q
}
`, extra, testRealm, hclPath(writeKeytab(t, dir))))
	return r, db, clk
}

// ⛔ One AS-REQ from anybody must not read the database. The realm read the
// set of sources on every request -- the whole people query of every SQL
// source, a subtree search of every ldap upstream -- so one unauthenticated
// UDP datagram read every backend in full. It now reads the snapshot.
//
// The witness is a database that can no longer be read: the people table is
// dropped after startup. A realm that queries it per request answers
// KDC_ERR_SVC_UNAVAILABLE (29); one that reads the snapshot still knows dora.
func TestARealmDoesNotReadTheDatabasePerRequest(t *testing.T) {
	r, db, _ := realmOverSQL(t, "")
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Fatalf("before: code %d, want PREAUTH_REQUIRED (25)", got)
	}
	execDB(t, db, "drop table staff")
	// The control: the database really is unreadable now.
	if _, err := r.srv.dir.Identities(); err == nil {
		t.Fatal("the sources still read after the table was dropped: the test proves nothing")
	}
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Errorf("after the table was dropped: code %d, want PREAUTH_REQUIRED (25) from the snapshot", got)
	}
	if got := asReqCode(t, r, "nobody"); got != errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN {
		t.Errorf("a name nobody has: code %d, want C_PRINCIPAL_UNKNOWN (6)", got)
	}
}

// max_age holds for the realm as it does for LDAP: past it, the KDC says the
// service is unavailable rather than issue tickets from data that old.
func TestARealmHonoursMaxAge(t *testing.T) {
	r, _, clk := realmOverSQL(t, `refresh = "1m"
max_age = "5m"`)
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Fatalf("fresh data: code %d, want PREAUTH_REQUIRED (25)", got)
	}
	clk.Advance(10 * time.Minute)
	if got := asReqCode(t, r, "dora"); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
		t.Errorf("data older than max_age: code %d, want SVC_UNAVAILABLE (29)", got)
	}
}
