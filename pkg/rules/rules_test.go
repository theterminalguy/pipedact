package rules

import (
	"strings"
	"testing"

	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
)

func TestRuleSafeguardLog(t *testing.T) {
	code := `
import { logger } from './logger';
logger.info("New registration received for user:", {
  email: "test@example.ca",
  sin: "046-454-286"
});`
	ctx := core.NewFileContext("/src/auth.ts", "src/auth.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleSafeguardLog{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for logging PII, got none")
	}
	if violations[0].PrincipleID != 7 {
		t.Errorf("expected principle 7, got %d", violations[0].PrincipleID)
	}
}

func TestRuleRawSIN(t *testing.T) {
	code := `const testSIN = "046-454-286";`
	ctx := core.NewFileContext("/src/auth.ts", "src/auth.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleRawSIN{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for hardcoded SIN, got none")
	}
	if violations[0].Severity != core.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", violations[0].Severity)
	}
}

func TestRuleConsentOptIn(t *testing.T) {
	code := `
await trackThirdPartyAdConversion({
  customerEmail: email,
  optInConfirmed: false
});`
	ctx := core.NewFileContext("/src/auth.ts", "src/auth.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleConsentOptIn{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for unconsented tracking, got none")
	}
	if violations[0].PrincipleID != 3 {
		t.Errorf("expected principle 3, got %d", violations[0].PrincipleID)
	}
}

func TestRuleOverCollection(t *testing.T) {
	code := `
const { email, healthCardNumber } = req.body;
await db.user.create({ data: { healthCardNumber } });`
	ctx := core.NewFileContext("/src/auth.ts", "src/auth.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleOverCollection{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for healthCard over-collection, got none")
	}
	if violations[0].PrincipleID != 4 {
		t.Errorf("expected principle 4, got %d", violations[0].PrincipleID)
	}
}

func TestRulePurposeUntagged(t *testing.T) {
	code := `
model UserAccount {
  id String @id
  canadianSIN String
}`
	ctx := core.NewFileContext("/prisma/schema.prisma", "prisma/schema.prisma", code)
	cfg := config.DefaultConfig()

	r := &RulePurposeUntagged{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for untagged schema field, got none")
	}
	if violations[0].PrincipleID != 2 {
		t.Errorf("expected principle 2, got %d", violations[0].PrincipleID)
	}
}

func TestRuleRetentionDisposal(t *testing.T) {
	code := `
model UserAccount {
  id String @id
  email String
}`
	ctx := core.NewFileContext("/prisma/schema.prisma", "prisma/schema.prisma", code)
	cfg := config.DefaultConfig()

	r := &RuleRetentionDisposal{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for missing retention policy, got none")
	}
	if violations[0].PrincipleID != 5 {
		t.Errorf("expected principle 5, got %d", violations[0].PrincipleID)
	}
}

func TestRuleIncompleteDSR(t *testing.T) {
	code := `
export async function generateUserArchive(userId: string) {
  const profile = await db.userProfile.findUnique({ where: { userId } });
  return { profile };
}`
	ctx := core.NewFileContext("/src/dsr.ts", "src/dsr.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleIncompleteDSR{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for incomplete DSR export, got none")
	}
	if violations[0].PrincipleID != 9 {
		t.Errorf("expected principle 9, got %d", violations[0].PrincipleID)
	}
}

func TestRuleHardcodedSecret(t *testing.T) {
	code := `const jwt_secret = "super_secret_signing_key_123456789";`
	ctx := core.NewFileContext("/src/auth.ts", "src/auth.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleHardcodedSecret{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for hardcoded secret, got none")
	}
	if violations[0].Severity != core.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", violations[0].Severity)
	}
	if violations[0].FrameworkMappings[core.FrameworkSOC2] != "CC6.1, CC6.6" {
		t.Errorf("expected CC6.1, CC6.6, got %s", violations[0].FrameworkMappings[core.FrameworkSOC2])
	}
}

func TestRuleInsecureCookie(t *testing.T) {
	code := `res.cookie('session_id', token, { secure: false });`
	ctx := core.NewFileContext("/src/auth.ts", "src/auth.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleInsecureCookie{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for insecure cookie, got none")
	}
	if violations[0].Severity != core.SeverityHigh {
		t.Errorf("expected HIGH severity, got %v", violations[0].Severity)
	}
}

func TestRuleWeakCrypto(t *testing.T) {
	code := `const hash = crypto.createHash('md5').update(pwd).digest('hex');`
	ctx := core.NewFileContext("/src/crypto.ts", "src/crypto.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleWeakCrypto{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for weak md5 crypto, got none")
	}
}

func TestRuleWildcardCORS(t *testing.T) {
	code := `app.use(cors({ origin: "*" }));`
	ctx := core.NewFileContext("/src/server.ts", "src/server.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleWildcardCORS{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for wildcard CORS, got none")
	}
}

func TestRuleRawSIN_Masking(t *testing.T) {
	rawSIN := "046-454-286"
	code := `const employeeSIN = "` + rawSIN + `";`
	ctx := core.NewFileContext("/src/employee.ts", "src/employee.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleRawSIN{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for SIN")
	}

	// Verify raw SIN is not in Message
	if strings.Contains(violations[0].Message, rawSIN) {
		t.Errorf("violation message leaked raw SIN: %s", violations[0].Message)
	}
	// Verify raw SIN is masked in LineText
	if strings.Contains(violations[0].LineText, rawSIN) {
		t.Errorf("violation LineText leaked raw SIN: %s", violations[0].LineText)
	}
	// Verify masked pattern exists
	if !strings.Contains(violations[0].Message, "***-***-286") {
		t.Errorf("expected masked SIN in message, got: %s", violations[0].Message)
	}
	if !strings.Contains(violations[0].LineText, "***-***-***") {
		t.Errorf("expected redacted SIN in LineText, got: %s", violations[0].LineText)
	}
}

func TestRuleHardcodedSecret_EnvFallback(t *testing.T) {
	code := `const apiKey = process.env.API_KEY || "sk_live_abcdef1234567890";`
	ctx := core.NewFileContext("/src/api.ts", "src/api.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleHardcodedSecret{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation for hardcoded secret fallback with process.env, got none")
	}
	// Verify secret is redacted in LineText
	if strings.Contains(violations[0].LineText, "sk_live_abcdef1234567890") {
		t.Errorf("secret not redacted in LineText: %s", violations[0].LineText)
	}
}

func TestRuleInsecureCookie_Isolation(t *testing.T) {
	code := `
// First cookie is secure
res.cookie('auth_token', token, {
  secure: true,
  httpOnly: true
});

// Second cookie is insecure
res.cookie('tracking_cookie', id, {
  secure: false
});
`
	ctx := core.NewFileContext("/src/routes.ts", "src/routes.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleInsecureCookie{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) != 1 {
		t.Fatalf("expected exactly 1 violation for tracking_cookie, got %d", len(violations))
	}
	if violations[0].Line != 9 {
		t.Errorf("expected violation on line 9, got line %d", violations[0].Line)
	}
}

func TestRuleConsentOptIn_LocalScope(t *testing.T) {
	// 20 lines of code between dummy function and tracking call
	code := `
function unrelated() {
  const hasConsentFor = true;
}
` + strings.Repeat("// filler line\n", 20) + `
async function sendEvent(email: string) {
  await trackThirdPartyAdConversion({ customerEmail: email });
}
`
	ctx := core.NewFileContext("/src/tracker.ts", "src/tracker.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleConsentOptIn{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation when consent check is far away outside enclosing block, got none")
	}
}

func TestRuleConsentOptIn_CommentGuard(t *testing.T) {
	// Consent guard is commented out with //
	code := `
async function sendEvent(email: string) {
  // if (hasConsentFor('marketing')) {
  await trackThirdPartyAdConversion({ customerEmail: email });
  // }
}
`
	ctx := core.NewFileContext("/src/tracker.ts", "src/tracker.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleConsentOptIn{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) == 0 {
		t.Fatalf("expected violation when consent guard is in comment, got none")
	}
	if violations[0].Confidence != core.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %s", violations[0].Confidence)
	}
}

func TestRuleTrackingInComment_NoViolation(t *testing.T) {
	code := `
// Example:
// await trackThirdPartyAdConversion({ customerEmail: 'test@example.com' });
function realCode() {
  return true;
}
`
	ctx := core.NewFileContext("/src/tracker.ts", "src/tracker.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleConsentOptIn{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for tracking call in comment, got %d", len(violations))
	}
}

func TestRuleHardcodedSecret_CommentNoViolation(t *testing.T) {
	code := `
// const apiKey = "sk_live_abcdef1234567890";
// Example key: AKIAIOSFODNN7EXAMPLE
function realCode() {
  return true;
}
`
	ctx := core.NewFileContext("/src/auth.ts", "src/auth.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleHardcodedSecret{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for secret in comment, got %d", len(violations))
	}
}

func TestRuleInsecureCookie_CommentNoViolation(t *testing.T) {
	code := `
// res.cookie('session', 'xyz', { secure: false });
function realCode() {
  return true;
}
`
	ctx := core.NewFileContext("/src/server.ts", "src/server.ts", code)
	cfg := config.DefaultConfig()

	r := &RuleInsecureCookie{}
	violations := r.Inspect(ctx, cfg)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for cookie in comment, got %d", len(violations))
	}
}
