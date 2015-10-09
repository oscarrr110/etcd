// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutil

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/etcd/Godeps/_workspace/src/github.com/coreos/pkg/capnslog"
)

var (
	plog = capnslog.NewPackageLogger("github.com/coreos/etcd/pkg", "netutil")

	// indirection for testing
	resolveTCPAddr = net.ResolveTCPAddr
)

// ResolveTCPAddrs is a convenience wrapper for net.ResolveTCPAddr.
// ResolveTCPAddrs resolves all DNS hostnames in-place for the given set of
// url.URLs.
func ResolveTCPAddrs(urls ...[]url.URL) error {
	for _, us := range urls {
		for i, u := range us {
			host, _, err := net.SplitHostPort(u.Host)
			if err != nil {
				plog.Errorf("could not parse url %s during tcp resolving", u.Host)
				return err
			}
			if host == "localhost" {
				continue
			}
			if net.ParseIP(host) != nil {
				continue
			}
			tcpAddr, err := resolveTCPAddr("tcp", u.Host)
			if err != nil {
				plog.Errorf("could not resolve host %s", u.Host)
				return err
			}
			plog.Infof("resolving %s to %s", u.Host, tcpAddr.String())
			us[i].Host = tcpAddr.String()
		}
	}
	return nil
}

// BasicAuth returns the username and password provided in the request's
// Authorization header, if the request uses HTTP Basic Authentication.
// See RFC 2617, Section 2.
// Based on the BasicAuth method from the Golang standard lib.
// TODO: use the standard lib BasicAuth method when we move to Go 1.4.
func BasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return
	}
	return parseBasicAuth(auth)
}


func CertAuth(r *http.Request) (username string, path string, ok bool)  {

	//      var certs []*x509.Certificate
	certChains := r.TLS.PeerCertificates
	cert := certChains[0]
	if cert != nil {
		userName := cert.Subject.CommonName
		path := cert.Subject.OrganizationalUnit[0]
		plog.Errorf("subject userName: %s, path: %s", userName, path)
		return userName,path, true
	}
	return
}

func ParseCertAuth(r *http.Request) (username string, role string ,path string, ok bool) {

	certChains := r.TLS.PeerCertificates
	cert := certChains[0]
	if cert != nil {

//		userName := cert.Subject.CommonName
//		role := cert.Subject.Organization[0]
//		path := cert.Subject.OrganizationalUnit[0]

		userRolePath := cert.Subject.CommonName
		plog.Errorf("userRolePath: %s", userRolePath)

		userRolePathArray := strings.Split(userRolePath, "|")
		userName := userRolePathArray[0]
		role := userRolePathArray[1]
		path := userRolePathArray[2]

		return userName,role,path,true
	}

	return
}


// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
// Taken from the Golang standard lib.
// TODO: use the standard lib BasicAuth method when we move to Go 1.4.
func parseBasicAuth(auth string) (username, password string, ok bool) {
	if !strings.HasPrefix(auth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}
