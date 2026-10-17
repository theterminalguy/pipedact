package rules

import (
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
