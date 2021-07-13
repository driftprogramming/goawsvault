package goawsvault

import (
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/aws"
	log "github.com/sirupsen/logrus"
)

// consts.
const (
	httpClientTimeout = 10 * time.Second
)

var httpClient = &http.Client{
	Timeout: httpClientTimeout,
}

// LoginWithinAwsEcsContainerAutomatically If the aws ecs container is running under a specific aws assume role,
// and this role is configured on Vault server side, then this method will query the aws assume role's credential in
// ECS container automatically and return a Vault client with valid token.
// NO need any other classic AWS credentials(AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY)
func LoginWithinAwsEcsContainerAutomatically(vaultHost string, awsRegion string) *api.Client {
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

// LoginByAwsRoleArn  A classic AWS credentials(AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY) is required for this function
// to execute AWS API to query the specific role. In general, you need to setup the AWS credential in env vars like
// this:
// _=os.Setenv("AWS_ACCESS_KEY_ID","AKKKAFYN9K3AUY74SNY39")
// _=os.Setenv("AWS_SECRET_ACCESS_KEY","ZTL9288NXdymfhxcISMOCU+AsYy9O3RsiDptABm8")
// Please note that you need to setup the trust configuration in AWS role console to make sure this credential have permission to
// query the awsRoleArn.
func LoginByAwsRoleArn(vaultHost string, awsRoleArn string, awsRegion string) *api.Client {
	token, err := getTokenByAwsRoleArn(vaultHost, awsRoleArn, awsRegion)
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

// Login In general, this method just call the vault login path you specified here.
// We usually use this to login in local env for developers. e.g:
// loginPath: auth/mycompany-dev/login
// data: map[string]interface{}{"role_id": "developer"}
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

func getTokenByAwsRoleArn(vaultHost string, awsRoleArn string, awsRegion string) (string, error) {
	sess := session.Must(session.NewSession())
	log.Info("awsRole: " + awsRoleArn + " REGION: " + awsRegion)
	creds := stscreds.NewCredentials(sess, awsRoleArn)
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
