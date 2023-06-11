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
	"fmt"
	"net/http"

	"github.com/jakob3xd/opensearch-golang"
	"github.com/jakob3xd/opensearch-golang/opensearchutil"
)

type UsersGetReq struct {
	User   string
	Header http.Header
}

func (r UsersGetReq) GetRequest() (*http.Request, error) {
	return opensearchutil.BuildRequest(
		"GET",
		fmt.Sprintf("%s%s%s", basePath, "api/internalusers/", r.User),
		nil,
		nil,
		r.Header,
	)
}

type UsersGetResp struct {
	Users    map[string]UserGetResp
	response *opensearch.Response
}

type UserGetResp struct {
	Reserved                bool              `json:"reserved"`
	Hidden                  bool              `json:"hidden"`
	BackendRoles            []string          `json:"backend_roles"`
	Attributes              map[string]string `json:"attributes"`
	OpensearchSecurityRoles []string          `json:"opendistro_security_roles"`
	Static                  bool              `json:"static"`
}

func (r UsersGetResp) Inspect() *opensearch.Inspect {
	return &opensearch.Inspect{Response: r.response}
}
