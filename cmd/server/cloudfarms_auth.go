package main

// Cloudfarms authorization: JWTs signed with a shared HS256 secret, carrying a role per namespace.
//
// Everything Cloudfarms-specific lives in this file and in the few lines of main.go that wire it in, so an upgrade of
// Temporal only has to carry these two files over.
//
// Environment:
//
//	JWT_SECRET                      the HS256 secret the tokens are signed with (required)
//	TEMPORAL_JWT_REQUIRE_EXPIRATION "true": a token without an "exp" claim is refused. Default false, because the
//	                                tokens issued so far have none - turn it on once they are re-issued
//	TEMPORAL_AUTH_ALLOW_TOKENLESS   "true": a call without a token gets system admin, the behaviour before
//	                                1.32. Only for the transition, until every client sends a token and the
//	                                internal-frontend is enabled. Default false: a call without a token is refused.
//	                                While it is on, every namespace and API still called without a token is logged
//	                                ("Call without a token allowed", at most every 10 minutes each), so the log shows
//	                                which clients still have to get a token before it is turned off
//
// Temporal's own components (the worker service, admin tools, the namespace job) must reach the server through the
// internal-frontend service, which upstream authorizes as system admin (authorization.NewInternalClaimMapper). With
// it enabled, the public frontend can refuse every call that has no valid token.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.temporal.io/server/common/api"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
)

// tokenless marks the claims of a call that had no token (only given while tokenless calls are allowed)
const tokenless = "cloudfarms-tokenless"

// Token payload: {"namespace_roles": {"feed-systems": "worker", ...}, "sub": "...", "exp": ...}
type cloudfarmsClaims struct {
	jwt.RegisteredClaims
	NamespaceRoles map[string]string `json:"namespace_roles"`
}

type cloudfarmsAuthConfig struct {
	secret            []byte
	requireExpiration bool
	allowTokenless    bool
}

func cloudfarmsAuthConfigFromEnv() (cloudfarmsAuthConfig, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return cloudfarmsAuthConfig{}, errors.New("JWT_SECRET environment variable is not set")
	}
	return cloudfarmsAuthConfig{
		secret:            []byte(secret),
		requireExpiration: strings.EqualFold(os.Getenv("TEMPORAL_JWT_REQUIRE_EXPIRATION"), "true"),
		allowTokenless:    strings.EqualFold(os.Getenv("TEMPORAL_AUTH_ALLOW_TOKENLESS"), "true"),
	}, nil
}

// ---- claim mapper

type cloudfarmsClaimMapper struct {
	cfg cloudfarmsAuthConfig
}

var (
	_ authorization.ClaimMapper                     = (*cloudfarmsClaimMapper)(nil)
	_ authorization.ClaimMapperWithAuthInfoRequired = (*cloudfarmsClaimMapper)(nil)
)

func newCloudfarmsClaimMapper(cfg cloudfarmsAuthConfig) *cloudfarmsClaimMapper {
	return &cloudfarmsClaimMapper{cfg: cfg}
}

// AuthInfoRequired false lets a call without a token reach GetClaims - only wanted while tokenless calls are allowed.
// Otherwise such a call has no claims, and the authorizer refuses it.
func (m *cloudfarmsClaimMapper) AuthInfoRequired() bool {
	return !m.cfg.allowTokenless
}

func (m *cloudfarmsClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	claims := &authorization.Claims{AuthType: "jwt", Namespaces: map[string]authorization.Role{}}

	token := strings.TrimSpace(authInfo.AuthToken)
	// Standard "Bearer <token>", or the bare token the clients have sent so far
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		if m.cfg.allowTokenless {
			claims.System = authorization.RoleAdmin
			claims.Extensions = tokenless
		}
		return claims, nil
	}

	parsed, err := jwt.ParseWithClaims(token, &cloudfarmsClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.cfg.secret, nil
	})
	if err != nil {
		// covers a bad signature and an "exp" / "nbf" / "iat" that is present and not valid now
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}
	custom, ok := parsed.Claims.(*cloudfarmsClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token claims")
	}
	// jwt/v4 checks "exp" only when the token has one - a token without it would never expire
	if m.cfg.requireExpiration && custom.ExpiresAt == nil {
		return nil, errors.New("JWT token has no expiration (exp)")
	}

	claims.Subject = custom.Subject
	for namespace, roleName := range custom.NamespaceRoles {
		role, err := roleFromName(roleName)
		if err != nil {
			return nil, err
		}
		claims.Namespaces[namespace] = role
	}
	return claims, nil
}

func roleFromName(name string) (authorization.Role, error) {
	switch name {
	case "worker":
		return authorization.RoleWorker, nil
	case "reader":
		return authorization.RoleReader, nil
	case "writer":
		return authorization.RoleWriter, nil
	case "admin":
		return authorization.RoleAdmin, nil
	default:
		return authorization.RoleUndefined, fmt.Errorf("invalid role in JWT token: %s", name)
	}
}

// ---- authorizer

// workerAPIs are what the "worker" role may call in its namespace: what an activity worker - e.g. a New Integrator on
// a farm PC - needs to poll its task queue, report heartbeats and results, and shut down. Listed by name: a rule like
// "contains Activity" would also allow PauseActivity, ResetActivity, UpdateActivityOptions, ... on every activity of
// the namespace.
var workerAPIs = map[string]bool{
	"PollActivityTaskQueue":            true,
	"RecordActivityTaskHeartbeat":      true,
	"RecordActivityTaskHeartbeatById":  true,
	"RespondActivityTaskCompleted":     true,
	"RespondActivityTaskCompletedById": true,
	"RespondActivityTaskFailed":        true,
	"RespondActivityTaskFailedById":    true,
	"RespondActivityTaskCanceled":      true,
	"RespondActivityTaskCanceledById":  true,
	"PollWorkflowTaskQueue":            true,
	"DescribeNamespace":                true,
	"RecordWorkerHeartbeat":            true,
	"ShutdownWorker":                   true,
}

// cloudfarmsAuthorizer is Temporal's default authorizer, plus the "worker" role, which the default ignores: a
// namespace "worker" may call the workerAPIs in that namespace, and nothing else.
type cloudfarmsAuthorizer struct {
	defaultAuthorizer authorization.Authorizer
	logger            log.Logger
	tokenlessLogged   sync.Map // namespace + API -> time.Time of the last log line
}

var _ authorization.Authorizer = (*cloudfarmsAuthorizer)(nil)

const tokenlessLogInterval = 10 * time.Minute

func newCloudfarmsAuthorizer(logger log.Logger) *cloudfarmsAuthorizer {
	return &cloudfarmsAuthorizer{defaultAuthorizer: authorization.NewDefaultAuthorizer(), logger: logger}
}

func (a *cloudfarmsAuthorizer) Authorize(ctx context.Context, claims *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	if claims != nil && claims.Extensions == tokenless {
		a.logTokenless(target)
	}
	if claims != nil && target.Namespace != "" {
		role := claims.System | claims.Namespaces[target.Namespace]
		// only a pure worker - a reader, writer or admin is decided by the default rules
		if role == authorization.RoleWorker {
			if workerAPIs[api.MethodName(target.APIName)] {
				return authorization.Result{Decision: authorization.DecisionAllow}, nil
			}
			return authorization.Result{Decision: authorization.DecisionDeny}, nil
		}
	}
	return a.defaultAuthorizer.Authorize(ctx, claims, target)
}

// logTokenless logs a call without a token, at most every tokenlessLogInterval per namespace and API
func (a *cloudfarmsAuthorizer) logTokenless(target *authorization.CallTarget) {
	if a.logger == nil {
		return
	}
	key := target.Namespace + "|" + target.APIName
	now := time.Now()
	if last, ok := a.tokenlessLogged.Load(key); ok && now.Sub(last.(time.Time)) < tokenlessLogInterval {
		return
	}
	a.tokenlessLogged.Store(key, now)
	a.logger.Warn("Call without a token allowed (TEMPORAL_AUTH_ALLOW_TOKENLESS) - this client needs a token",
		tag.WorkflowNamespace(target.Namespace), tag.String("api", api.MethodName(target.APIName)))
}

// cloudfarmsAuth replaces the authorizer and claim mapper of the server's config
func cloudfarmsAuth(_ *config.Config, logger log.Logger) (authorization.Authorizer, authorization.ClaimMapper, cloudfarmsAuthConfig, error) {
	cfg, err := cloudfarmsAuthConfigFromEnv()
	if err != nil {
		return nil, nil, cfg, err
	}
	return newCloudfarmsAuthorizer(logger), newCloudfarmsClaimMapper(cfg), cfg, nil
}
