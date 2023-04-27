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

	"github.com/jakob3xd/opensearch-golang"
)

type usersClient struct {
	client *opensearch.Client
}

func newUsersClient(client *opensearch.Client) usersClient {
	return usersClient{client: client}
}

func (c usersClient) Get(ctx context.Context, req UsersGetReq) (*UsersGetResp, error) {
	_, err := c.client.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	return nil, nil
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

func (u UsersGet) Do(ctx context.Context, transport Transport) (*UsersGetResp, error) {
	var (
		path   strings.Builder
		params map[string]string

		data PointInTimeCreateResp
	)
	method := "POST"

	if req == nil {
		return nil, nil, ErrRequestNilPointer
	}

	path.Grow(1 + len(strings.Join(req.Index, ",")) + len("/_search/point_in_time"))
	path.WriteString("/")
	path.WriteString(strings.Join(req.Index, ","))
	path.WriteString("/_search/point_in_time")

	params = req.Params.get()

	response, err := performRequest(ctx, client.transport, method, path.String(), nil, params, req.Header)

	if err = response.Err(); err != nil {
		return response, nil, err
	}

	if len(req.Params.FilterPath) != 0 {
		return response, nil, nil
	}

	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return response, nil, err
	}
	return response, &data, nil
}

func (u UsersDelete) Do(ctx context.Context, transport Transport) error {
	var (
		method string
		path   strings.Builder
	)
	method = "DELETE"
	path.Grow(len("/_plugins/_security/api/internalusers/") + len(u.User))
	path.WriteString("/_plugins/_security/api/internalusers/")
	path.WriteString(u.User)

	req, err := newRequest(method, path.String(), nil)
	if err != nil {
		return err
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}
	resp, err := transport.Perform(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return errorCheck(resp, []int{200, 404})
}

func (u UsersCreate) Do(ctx context.Context, transport Transport) error {
	var (
		method string
		path   strings.Builder
	)
	method = "PUT"
	path.Grow(len("/_plugins/_security/api/internalusers/") + len(u.User))
	path.WriteString("/_plugins/_security/api/internalusers/")
	path.WriteString(u.User)
	body, err := json.Marshal(u.Body)
	if err != nil {
		return err
	}

	req, err := newRequest(method, path.String(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	if u.Body != nil {
		req.Header[headerContentType] = headerContentTypeJSON
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}
	resp, err := transport.Perform(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return errorCheck(resp, []int{200, 201, 404})
}
*/
