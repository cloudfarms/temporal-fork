package main

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.temporal.io/server/common/authorization"
)

const testSecret = "test-secret"

func token(t *testing.T, secret string, roles map[string]string, expiresAt *time.Time) string {
	t.Helper()
	claims := cloudfarmsClaims{NamespaceRoles: roles}
	claims.Subject = "integrator-6935"
	if expiresAt != nil {
		claims.ExpiresAt = jwt.NewNumericDate(*expiresAt)
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func mapper(requireExpiration, allowTokenless bool) *cloudfarmsClaimMapper {
	return newCloudfarmsClaimMapper(cloudfarmsAuthConfig{
		secret: []byte(testSecret), requireExpiration: requireExpiration, allowTokenless: allowTokenless,
	})
}

func authorize(t *testing.T, claims *authorization.Claims, namespace, method string) authorization.Decision {
	t.Helper()
	result, err := newCloudfarmsAuthorizer(nil).Authorize(context.Background(), claims, &authorization.CallTarget{
		APIName:   "/temporal.api.workflowservice.v1.WorkflowService/" + method,
		Namespace: namespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Decision
}

func TestRolesPerNamespace(t *testing.T) {
	claims, err := mapper(false, false).GetClaims(&authorization.AuthInfo{
		AuthToken: token(t, testSecret, map[string]string{"feed-systems": "worker", "other": "admin"}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Namespaces["feed-systems"] != authorization.RoleWorker || claims.Namespaces["other"] != authorization.RoleAdmin {
		t.Fatalf("unexpected roles %v", claims.Namespaces)
	}
	if claims.System != authorization.RoleUndefined || claims.Subject != "integrator-6935" {
		t.Fatalf("unexpected system role %v / subject %q", claims.System, claims.Subject)
	}
}

func TestBearerPrefixIsAccepted(t *testing.T) {
	_, err := mapper(false, false).GetClaims(&authorization.AuthInfo{
		AuthToken: "Bearer " + token(t, testSecret, map[string]string{"feed-systems": "writer"}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWrongSecretIsRefused(t *testing.T) {
	_, err := mapper(false, false).GetClaims(&authorization.AuthInfo{
		AuthToken: token(t, "another-secret", map[string]string{"feed-systems": "admin"}, nil),
	})
	if err == nil {
		t.Fatal("a token signed with another secret was accepted")
	}
}

func TestExpiredTokenIsRefused(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	_, err := mapper(false, false).GetClaims(&authorization.AuthInfo{
		AuthToken: token(t, testSecret, map[string]string{"feed-systems": "admin"}, &past),
	})
	if err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestTokenWithoutExpiration(t *testing.T) {
	noExp := &authorization.AuthInfo{AuthToken: token(t, testSecret, map[string]string{"feed-systems": "admin"}, nil)}
	if _, err := mapper(false, false).GetClaims(noExp); err != nil {
		t.Fatalf("without TEMPORAL_JWT_REQUIRE_EXPIRATION a token without exp must still work: %v", err)
	}
	if _, err := mapper(true, false).GetClaims(noExp); err == nil {
		t.Fatal("with TEMPORAL_JWT_REQUIRE_EXPIRATION a token without exp was accepted")
	}
	future := time.Now().Add(time.Hour)
	withExp := &authorization.AuthInfo{AuthToken: token(t, testSecret, map[string]string{"feed-systems": "admin"}, &future)}
	if _, err := mapper(true, false).GetClaims(withExp); err != nil {
		t.Fatal(err)
	}
}

func TestTokenlessCall(t *testing.T) {
	// refused: no auth info reaches the mapper, the call has no claims and the authorizer denies it
	if !mapper(false, false).AuthInfoRequired() {
		t.Fatal("tokenless calls must not reach the claim mapper by default")
	}
	if authorize(t, nil, "feed-systems", "StartWorkflowExecution") != authorization.DecisionDeny {
		t.Fatal("a call without claims was allowed")
	}

	// transition: TEMPORAL_AUTH_ALLOW_TOKENLESS keeps the behaviour before 1.32
	m := mapper(false, true)
	claims, err := m.GetClaims(&authorization.AuthInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if m.AuthInfoRequired() || claims.System != authorization.RoleAdmin {
		t.Fatal("with TEMPORAL_AUTH_ALLOW_TOKENLESS a tokenless call must be system admin")
	}
}

func TestWorkerRole(t *testing.T) {
	worker := &authorization.Claims{Namespaces: map[string]authorization.Role{"feed-systems": authorization.RoleWorker}}
	for _, allowed := range []string{"PollActivityTaskQueue", "RecordActivityTaskHeartbeat", "RespondActivityTaskCompleted", "DescribeNamespace"} {
		if authorize(t, worker, "feed-systems", allowed) != authorization.DecisionAllow {
			t.Errorf("worker must be allowed %s", allowed)
		}
	}
	for _, denied := range []string{"PauseActivity", "ResetActivity", "UpdateActivityOptions", "StartWorkflowExecution", "TerminateWorkflowExecution"} {
		if authorize(t, worker, "feed-systems", denied) != authorization.DecisionDeny {
			t.Errorf("worker must not be allowed %s", denied)
		}
	}
	if authorize(t, worker, "other", "PollActivityTaskQueue") != authorization.DecisionDeny {
		t.Error("worker of one namespace must not poll another")
	}
	if authorize(t, worker, "", "GetSystemInfo") != authorization.DecisionAllow {
		t.Error("GetSystemInfo is a health check, allowed to everyone")
	}
}

func TestOtherRolesFollowTheDefaultRules(t *testing.T) {
	writer := &authorization.Claims{Namespaces: map[string]authorization.Role{"feed-systems": authorization.RoleWriter}}
	if authorize(t, writer, "feed-systems", "StartWorkflowExecution") != authorization.DecisionAllow {
		t.Error("writer must start workflows")
	}
	if authorize(t, writer, "feed-systems", "UpdateNamespace") != authorization.DecisionDeny {
		t.Error("writer must not update the namespace")
	}
}
