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
	"io"
	"net/http"
)

type UsersDeleteReq struct {
	User   string
	Header http.Header
}

func (r UsersDeleteReq) GetMethod() string {
	return "DELETE"
}

func (r UsersDeleteReq) GetPath() string {
	return fmt.Sprintf("%s%s%s", basePath, "api/internalusers/", r.User)
}

func (r UsersDeleteReq) GetBody() (io.Reader, error) {
	return nil, nil
}

func (r UsersDeleteReq) GetParams() map[string]string {
	return nil
}

func (r UsersDeleteReq) GetHeader() http.Header {
	return r.Header
}

type UsersDeleteResp struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}
