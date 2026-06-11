/*
Copyright 2026 ZerBytes UG (haftungsbeschränkt).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zerbytes/nats-k8s-based-resolver/test/utils"
)

func applyManifest(manifest string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-", "-n", namespace)
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	return err
}

func deleteKubectlResource(kind, name string) {
	cmd := exec.Command("kubectl", "delete", kind, name, "-n", namespace, "--ignore-not-found=true", "--wait=false")
	_, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "warning: failed to delete %s/%s: %v\n", kind, name, err)
	}
}

func waitForAccount(name string) accountJSON {
	var account accountJSON
	Eventually(func(g Gomega) {
		fetched, err := getAccount(name)
		g.Expect(err).NotTo(HaveOccurred())
		account = fetched
		g.Expect(account.Status.Ready).To(BeTrue())
		g.Expect(account.Status.SecretName).To(Equal("nats-account-" + name + "-jwt"))
		g.Expect(account.Status.AccountPublicKey).NotTo(BeEmpty())
		g.Expect(account.Status.SigningKeyPublicKey).NotTo(BeEmpty())
	}, 3*time.Minute, time.Second).Should(Succeed())

	return account
}

func waitForUser(name string) userJSON {
	var user userJSON
	Eventually(func(g Gomega) {
		fetched, err := getUser(name)
		g.Expect(err).NotTo(HaveOccurred())
		user = fetched
		g.Expect(user.Status.Ready).To(BeTrue())
		g.Expect(user.Status.SecretName).To(Equal("nats-user-" + name + "-jwt"))
		g.Expect(user.Status.UserPublicKey).NotTo(BeEmpty())
		g.Expect(user.Status.SigningKeyPublicKey).NotTo(BeEmpty())
	}, 3*time.Minute, time.Second).Should(Succeed())

	return user
}

func getAccount(name string) (accountJSON, error) {
	var account accountJSON
	output, err := kubectlGetJSON("natsaccount", name)
	if err != nil {
		return account, err
	}
	err = json.Unmarshal([]byte(output), &account)
	return account, err
}

func getUser(name string) (userJSON, error) {
	var user userJSON
	output, err := kubectlGetJSON("natsuser", name)
	if err != nil {
		return user, err
	}
	err = json.Unmarshal([]byte(output), &user)
	return user, err
}

func kubectlGetJSON(kind, name string) (string, error) {
	cmd := exec.Command("kubectl", "get", kind, name, "-n", namespace, "-o", "json")
	output, err := utils.Run(cmd)
	if err != nil {
		return "", err
	}
	return output, nil
}

func waitForSecretData(name string) map[string]string {
	var secretData map[string]string
	Eventually(func(g Gomega) {
		fetched, err := getSecretData(name)
		g.Expect(err).NotTo(HaveOccurred())
		secretData = fetched
		g.Expect(secretData).NotTo(BeNil())
	}, 3*time.Minute, time.Second).Should(Succeed())

	return secretData
}

func getSecretData(name string) (map[string]string, error) {
	var secret secretJSON
	output, err := kubectlGetJSON("secret", name)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(output), &secret); err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func decodeSecretValue(v string) string {
	raw, err := base64.StdEncoding.DecodeString(v)
	Expect(err).NotTo(HaveOccurred())
	return string(raw)
}

func decodeAccountClaims(jwtStr string) *natsjwt.AccountClaims {
	claim, err := natsjwt.Decode(jwtStr)
	Expect(err).NotTo(HaveOccurred())

	accountClaim, ok := claim.(*natsjwt.AccountClaims)
	Expect(ok).To(BeTrue())
	return accountClaim
}

func decodeUserClaims(creds string) *natsjwt.UserClaims {
	jwtStr, seedStr := extractJWTAndSeed(creds)
	Expect(jwtStr).NotTo(BeEmpty())
	Expect(seedStr).NotTo(BeEmpty())

	claim, err := natsjwt.Decode(jwtStr)
	Expect(err).NotTo(HaveOccurred())

	userClaim, ok := claim.(*natsjwt.UserClaims)
	Expect(ok).To(BeTrue())
	return userClaim
}

func extractJWTAndSeed(creds string) (jwt string, seed string) {
	lines := strings.Split(strings.TrimSpace(creds), "\n")
	for i, line := range lines {
		switch line {
		case "---- BEGIN NATS USER JWT ----":
			if i+1 < len(lines) {
				jwt = lines[i+1]
			}
		case "-----BEGIN USER NKEY SEED-----":
			if i+1 < len(lines) {
				seed = lines[i+1]
			}
		}
	}

	return jwt, seed
}

type accountJSON struct {
	Status struct {
		Ready               bool   `json:"ready"`
		AccountPublicKey    string `json:"accountPublicKey"`
		SecretName          string `json:"secretName"`
		SigningKeyPublicKey string `json:"signingKeyPublicKey"`
	} `json:"status"`
}

type userJSON struct {
	Status struct {
		Ready               bool   `json:"ready"`
		UserPublicKey       string `json:"userPublicKey"`
		SecretName          string `json:"secretName"`
		SigningKeyPublicKey string `json:"signingKeyPublicKey"`
	} `json:"status"`
}

type secretJSON struct {
	Data map[string]string `json:"data"`
}
