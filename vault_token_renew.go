package goawsvault

import (
	"context"
	"errors"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

func NewTokenManager(ctx context.Context, client *vault.Client) *TokenManager {
	return &TokenManager{
		ctx:    ctx,
		client: client,
	}
}

type TokenManager struct {
	ctx    context.Context
	client *vault.Client
}

func (tm *TokenManager) MonitoringForToken() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		secret, err := tm.client.Auth().Token().RenewSelf(0)
		if err != nil {
			logrus.WithError(err).Error("token could not be renewed, resetting")
			time.Sleep(time.Second * 1)
			continue
		}

		tokenRenewable, err := secret.TokenIsRenewable()
		if err != nil {
			logrus.WithError(err).Error("can't determine if token is renewable")
			time.Sleep(time.Second * 1)
			continue
		}

		if !tokenRenewable {
			logrus.Error("token isn't renewable")
			time.Sleep(time.Second * 1)
			continue
		}

		go tm.renewToken()
		return
	}
}

func (tm *TokenManager) renewToken() {
	for {
		secret, err := tm.client.Auth().Token().RenewSelf(0)
		if err != nil {
			var responseError *vault.ResponseError
			if errors.As(err, &responseError) {
				if responseError.StatusCode == 403 { //nolintgomnd
					logrus.WithError(err).Error("access denied, renew failed")
					tm.MonitoringForToken()
					return
				}
			}
			logrus.WithError(err).Error("failed to renew Vault token")
			time.Sleep(time.Second * 1)
			continue
		}

		duration := time.Duration(secret.Auth.LeaseDuration) * time.Second
		logrus.WithField("duration", duration).Debug("Vault token renewed")

		select {
		case <-tm.ctx.Done():
			return
		case <-time.After(duration / 2): //nolintgomnd Start trying to renew at the halfway point
			continue
		}
	}
}
