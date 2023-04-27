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
	"github.com/jakob3xd/opensearch-golang"
)

type Config struct {
	Client opensearch.Config
}

type Client struct {
	client *opensearch.Client
	Users  usersClient
}

func clientInit(rootClient *opensearch.Client) *Client {
	return &Client{
		client: rootClient,
		Users:  newUsersClient(rootClient),
	}
}

// NewClient returns a security client
func NewClient(config Config) (*Client, error) {
	rootClient, err := opensearch.NewClient(config.Client)
	if err != nil {
		return nil, err
	}
	return clientInit(rootClient), nil
}

// NewDefaultClient returns a secure client using defauls
func NewDefaultClient() (*Client, error) {
	rootClient, err := opensearch.NewDefaultClient()
	if err != nil {
		return nil, err
	}
	return clientInit(rootClient), nil
}
