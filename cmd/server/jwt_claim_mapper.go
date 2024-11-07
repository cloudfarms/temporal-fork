// The MIT License
//
// Copyright (c) 2020 Temporal Technologies Inc.  All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"os"
)

// Custom claims structure for JWT token
type CustomClaims struct {
	jwt.RegisteredClaims
	// Store namespace-role pairs as a map in the JWT token
	NamespaceRoles map[string]string `json:"namespace_roles"`
}

type jwtClaimMapper struct {
	jwtSecret []byte
}

func NewJwtClaimMapper(_ *config.Config) authorization.ClaimMapper {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		panic("JWT_SECRET environment variable is not set")
	}
	return &jwtClaimMapper{
		jwtSecret: []byte(jwtSecret),
	}
}

func (c jwtClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	claims := authorization.Claims{}
	claims.Namespaces = make(map[string]authorization.Role)

	// If no AuthToken is present, set system role to admin and return
	if authInfo.AuthToken == "" {
		claims.System = authorization.RoleAdmin
		return &claims, nil
	}

	// Parse JWT token
	token, err := jwt.ParseWithClaims(authInfo.AuthToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return c.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Type assert and get custom claims
	if customClaims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		// Convert namespace roles from the JWT token to the claims structure
		for namespace, roleStr := range customClaims.NamespaceRoles {
			// Convert string role to authorization.Role
			var role authorization.Role
			switch roleStr {
			case "worker":
				role = authorization.RoleWorker
			case "reader":
				role = authorization.RoleReader
			case "writer":
				role = authorization.RoleWriter
			case "admin":
				role = authorization.RoleAdmin
			default:
				return nil, fmt.Errorf("invalid role in JWT token: %s", roleStr)
			}
			claims.Namespaces[namespace] = role
		}
	} else {
		return nil, fmt.Errorf("invalid token claims")
	}

	return &claims, nil
}
