// SPDX-License-Identifier: Apache-2.0
//
// The OpenSearch Contributors require contributions made to
// this file be licensed under the Apache-2.0 license or a
// compatible open source license.
//
// Modifications Copyright OpenSearch Contributors. See
// GitHub history for details.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"context"
)

const basePath = "/_plugins/_security/"

type usersClient struct {
	securityClient *Client
}

func (c usersClient) Get(ctx context.Context, req *UsersGetReq) (*UsersGetResp, error) {
	users := make(UsersGetResp)
	_, err := c.securityClient.do(ctx, req, &users)
	if err != nil {
		return nil, err
	}
	return &users, nil
}

func (c usersClient) Delete(ctx context.Context, req *UsersDeleteReq) (*UsersDeleteResp, error) {
	var users UsersDeleteResp
	_, err := c.securityClient.do(ctx, req, &users)
	if err != nil {
		return nil, err
	}
	return &users, nil
}

/*

type UsersDelete struct {
	User string
}
type UsersCreate struct {
	User string
	Body *UsersCreateBody
}
type UsersCreateBody struct {
	Password                string            `json:"password,omitempty"`
	Hash                    string            `json:"hash,omitempty"`
	OpensearchSecurityRoles []string          `json:"opendistro_security_roles,omitempty"`
	BackendRoles            []string          `json:"backend_roles,omitempty"`
	Attributes              map[string]string `json:"attributes,omitempty"`
}

type UsersPatch struct {
	User string
	Body []UsersPatchBody
}
type UsersPatchBody struct {
	Op    string
	Path  string
	Value UsersPatchBodyValue
}

type UsersPatchBodyValue any

*/
