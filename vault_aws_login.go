package goawsvault

import (
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/aws"
	log "github.com/sirupsen/logrus"
)

// consts.
const (
	httpClientTimeout = 10 * time.Second
)

var httpClient = &http.Client{ //nolintgochecknoglobals
	Timeout: httpClientTimeout,
}

func LoginByAwsEcsRole(vaultHost string, awsRegion string) *api.Client {
	token, err := getTokenInAwsEcsContainer(vaultHost, awsRegion)
	if err != nil {
		panic(err)
	}

	client, err := api.NewClient(&api.Config{Address: vaultHost, HttpClient: httpClient})
	if err != nil {
		panic(err)
	}

	client.SetToken(token)
	return client
}

func Login(vaultHost string, loginPath string, data map[string]interface{}) *api.Client {
	token, err := getToken(vaultHost, loginPath, data)
	if err != nil {
		panic(err)
	}

	client, err := api.NewClient(&api.Config{Address: vaultHost, HttpClient: httpClient})
	if err != nil {
		panic(err)
	}

	client.SetToken(token)
	return client
}

func getToken(vaultHost string, loginPath string, data map[string]interface{}) (string, error) {
	client, err := api.NewClient(&api.Config{Address: vaultHost, HttpClient: httpClient})
	if err != nil {
		return "", err //nolintwrapcheck
	}

	secret, err := client.Logical().Write(loginPath, data)
	if err != nil {
		log.WithError(err).Fatal("failed to login to dev model")
	}

	tokenID, err := secret.TokenID()
	if err != nil {
		log.WithError(err).Fatal("failed extract token from secret")
	}

	log.Info("Got dev model vault token")
	return tokenID, nil
}

func getTokenInAwsEcsContainer(vaultHost string, awsRegion string) (string, error) {
	ds := defaults.Get()
	credsProvider := defaults.RemoteCredProvider(*ds.Config, ds.Handlers)
	creds := credentials.NewCredentials(credsProvider)
	_, err := creds.Get()
	if err != nil {
		return "", err //nolintwrapcheck
	}

	log.Info("Get container AWS ECS credential success!")
	data, err := awsauth.GenerateLoginData(creds, "", awsRegion)
	if err != nil {
		return "", err //nolintwrapcheck
	}

	client, err := api.NewClient(&api.Config{Address: vaultHost, HttpClient: httpClient})
	if err != nil {
		return "", err //nolintwrapcheck
	}

	secret, err := client.Logical().Write("auth/aws/login", data)
	if err != nil {
		return "", err //nolintwrapcheck
	}

	token := secret.Auth.ClientToken
	return token, nil
}
