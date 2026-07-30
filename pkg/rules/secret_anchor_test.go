package rules

import (
	"math/rand"
	"strings"
	"testing"
)

// The anchor pre-filter is only sound if every anchor set is a *necessary*
// condition for its pattern to match. If a pattern could ever match content
// containing none of its anchors, the filter would silently drop a real
// finding. This asserts that property directly: whenever a pattern matches,
// its anchors must have been satisfied.
func TestSecretPatternAnchors_AreNecessaryConditions(t *testing.T) {
	corpus := []string{
		`api_key: "AKIAIOSFODNN7EXAMPLE12345"`,
		`API-KEY = 'abcdefghijklmnop'`,
		`apikey: "supersecretvalue123"`,
		`secret: "mysupersecretvalue"`,
		`TOKEN="abcdefghijklmnopqrst"`,
		`password: 'hunter2hunter2hunter2'`,
		`pwd: "abcdefghijklmn"`,
		`credential: "abcdefghijklmnopqr"`,
		`auth_key: "abcdefghijklmnopqrst"`,
		`aws_secret_access_key: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"`,
		`AMAZON_SESSION_TOKEN: "abcdefghijklmnopqrstuvwxyz"`,
		`gcp_private_key: "abcdefghijklmnopqrstuvwxyz"`,
		`GOOGLE_SERVICE_ACCOUNT="abcdefghijklmnopqrstuvwx"`,
		`azure_client_secret: "abcdefghijklmnopqrst"`,
		`MICROSOFT_TENANT_ID: "abcdefghijklmnopqrst"`,
		`github_token: "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		`gitlab-personal-access-token: "abcdefghijklmnopqrstuvwx"`,
		`bitbucket_pat: "abcdefghijklmnopqrstuvwx"`,
		`ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
		`gho_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`,
		`ghu_cccccccccccccccccccccccccccccccccccc`,
		`ghs_dddddddddddddddddddddddddddddddddddd`,
		`ghr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`,
		`database_url: "postgres://user:pass@host:5432/dbname"`,
		`db-url = "mysql://user:password@localhost/db"`,
		`connection_string: "Server=x;Database=y;User=z;Pass=w;"`,
		`MONGODB_URI: "mongodb://user:pass@host:27017"`,
		`redis_connection: "redis://localhost:6379"`,
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123`,
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		`oauth_token: "abcdefghijklmnopqrstuvwx"`,
		`bearer-token = 'abcdefghijklmnopqrstuvwx'`,
		`client_secret: "abcdefghijklmnopqrstuvwx"`,
		`client_id: "abcdefghijklmnopqrstuvwx"`,
		`https://hooks.slack.com/services/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
		`https://discordapp.com/api/webhooks/123456789/abcdefgh-ijkl`,
		`https://discord.com/api/webhooks/987654321/zyxwvu`,
		`bitcoin_private_key: "abcdefghijklmnopqrstuvwxyz123"`,
		`ETH_WALLET_KEY: "abcdefghijklmnopqrstuvwxyz123"`,
		`btc-wallet-key: "abcdefghijklmnopqrstuvwxyz123"`,
		`sendgrid_api_key: "SG.abcdefghijklmnopqrstuv"`,
		`mailgun_secret: "key-abcdefghijklmnopqrst"`,
		`ses_api_key: "abcdefghijklmnopqrstuvwx"`,
		`"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w"`,
		`name: CI`,
		`uses: actions/checkout@v4`,
		`run: npm ci && make build`,
	}

	for _, text := range corpus {
		lower := strings.ToLower(text)
		for i, sp := range hardcodedSecretPatterns {
			if sp.re.MatchString(text) && !sp.mayMatch(lower) {
				t.Errorf("pattern %d matched %q but its anchors %v were not satisfied; "+
					"the pre-filter would drop this finding", i, text, sp.anchors)
			}
		}
	}
}

// Randomised differential check over generated strings, to catch anchor sets
// that are necessary for the hand-written corpus but not in general.
func TestSecretPatternAnchors_RandomisedDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	fragments := []string{
		"api", "key", "_", "-", "secret", "token", "password", "pwd", "credential",
		"auth", "aws", "amazon", "gcp", "google", "azure", "microsoft", "github",
		"gitlab", "bitbucket", "ghp_", "gho_", "database", "db", "url", "connection",
		"string", "mongodb", "postgres", "mysql", "redis", "eyJ", "-----BEGIN",
		"PRIVATE", "KEY", "OPENSSH", "RSA", "oauth", "bearer", "client", "id",
		"discord", "slack", "bitcoin", "btc", "ethereum", "eth", "sendgrid",
		"mailgun", "ses", ":", "=", " ", `"`, "'", "abcdefghijklmnopqrstuvwxyz0123456789",
	}

	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := 0; j < 1+rng.Intn(8); j++ {
			b.WriteString(fragments[rng.Intn(len(fragments))])
		}
		text := b.String()
		lower := strings.ToLower(text)

		for k, sp := range hardcodedSecretPatterns {
			if sp.re.MatchString(text) && !sp.mayMatch(lower) {
				t.Fatalf("pattern %d matched %q but anchors %v were not satisfied",
					k, text, sp.anchors)
			}
		}
	}
}
