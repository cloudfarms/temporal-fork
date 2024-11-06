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
	"github.com/davecgh/go-spew/spew"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
)

type jwtClaimMapper struct{}

func NewJwtClaimMapper(_ *config.Config) authorization.ClaimMapper {
	spew.Dump("NewJwtClaimMapper called -> returning reference")

	return &jwtClaimMapper{}
}

func (c jwtClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	spew.Dump("GetClaims invoked (spew)")
	claims := authorization.Claims{}

	println("------ authInfo - START ------")
	spew.Dump(authInfo.AuthToken)
	spew.Dump(authInfo)
	println("------ authInfo - END ------")

	claims.System = authorization.RoleAdmin

	/*	if authInfo.TLSConnection != nil {
			spew.Dump("Some SSL info found, let's parse it")

			// Add claims based on client's TLS certificate
			claims.Subject = authInfo.TLSSubject.CommonName

			// ToDo: Server won't have "tls-sample" here but something else
			// allow server to do anything
			if authInfo.TLSSubject.CommonName == "cf-integrator-server" {
				spew.Dump("Authenticating a server")
				claims.System = authorization.RoleAdmin
			} else {
				// allow workers to implement activities
				spew.Dump("Authenticating a client")
				claims.Namespaces = make(map[string]authorization.Role)
				claims.Namespaces[authInfo.TLSSubject.CommonName] = authorization.RoleWorker
			}
		} else {
			spew.Dump("No SSL info found - no ClaimMapper logic applied")
		}*/
	/* 	if authInfo.AuthToken != "" {
	   		// Extract claims from the auth token and translate them into Temporal roles for the caller
	   		// Here we'll simply hardcode some as an example
	   		claims.System = authorization.RoleWriter // cluster-level admin
	   		claims.Namespaces = make(map[string]authorization.Role)
	   		claims.Namespaces["foo"] = authorization.RoleReader // caller has a reader role for the "foo" namespace
	   	}
	*/
	return &claims, nil
}
