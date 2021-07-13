package example

import (
	"context"
	"os"

	"github.com/driftprogramming/goawsvault"
	"github.com/hashicorp/vault/api"
)

func vaultLoginExample() *api.Client {
	vaultClient := goawsvault.Login("https://vault.mycompany.net", "auth/mycompany-dev/login", map[string]interface{}{"role_id": "developer"})
	tm := goawsvault.NewTokenManager(context.Background(), vaultClient)
	tm.MonitoringForToken() // renew vault token automatically
	return vaultClient
}

func vaultLoginWithinAwsEcsContainerAutomaticallyExample() *api.Client {
	vaultClient := goawsvault.LoginWithinAwsEcsContainerAutomatically("https://vault.mycompany.net", "eu-west-1")
	tm := goawsvault.NewTokenManager(context.Background(), vaultClient)
	tm.MonitoringForToken() // renew vault token automatically
	return vaultClient
}

func vaultLoginByAwsRoleArnExample() *api.Client {
	_ = os.Setenv("AWS_ACCESS_KEY_ID", "AKKKAFYN9K3AUY74SNY39") // the parent aws credentials to call aws api to assume the specific role
	_ = os.Setenv("AWS_SECRET_ACCESS_KEY", "ZTL9288NXdymfhxcISMOCU+AsYy9O3RsiDptABm8")
	vaultClient := goawsvault.LoginByAwsRoleArn("https://vault.mycompany.net", "arn:aws:iam::468785217309:role/my-application-service-dev", "eu-west-1")
	tm := goawsvault.NewTokenManager(context.Background(), vaultClient)
	tm.MonitoringForToken() // renew vault token automatically
	return vaultClient
}
