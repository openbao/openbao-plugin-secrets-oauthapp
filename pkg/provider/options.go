package provider

import (
	"net/url"

	"golang.org/x/oauth2"
)

type WithRedirectURL string

var (
	_ AuthCodeURLOption      = WithRedirectURL("")
	_ AuthCodeExchangeOption = WithRedirectURL("")
)

func (wru WithRedirectURL) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	target.RedirectURL = string(wru)
}

func (wru WithRedirectURL) ApplyToAuthCodeExchangeOptions(target *AuthCodeExchangeOptions) {
	target.RedirectURL = string(wru)
}

type WithScopes []string

var (
	_ AuthCodeURLOption       = WithScopes(nil)
	_ DeviceCodeAuthOption    = WithScopes(nil)
	_ ClientCredentialsOption = WithScopes(nil)
	_ TokenExchangeOption     = WithScopes(nil)
)

func (ws WithScopes) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	target.Scopes = append(target.Scopes, ws...)
}

func (ws WithScopes) ApplyToDeviceCodeAuthOptions(target *DeviceCodeAuthOptions) {
	target.Scopes = append(target.Scopes, ws...)
}

func (ws WithScopes) ApplyToClientCredentialsOptions(target *ClientCredentialsOptions) {
	target.Scopes = append(target.Scopes, ws...)
}

func (ws WithScopes) ApplyToTokenExchangeOptions(target *TokenExchangeOptions) {
	target.Scopes = append(target.Scopes, ws...)
}

type WithAudiences []string

var _ TokenExchangeOption = WithAudiences(nil)

func (wa WithAudiences) ApplyToTokenExchangeOptions(target *TokenExchangeOptions) {
	target.Audiences = append(target.Audiences, wa...)
}

type WithResources []string

var _ TokenExchangeOption = WithResources(nil)

func (wr WithResources) ApplyToTokenExchangeOptions(target *TokenExchangeOptions) {
	target.Resources = append(target.Resources, wr...)
}

type WithURLParams map[string]string

var (
	_ AuthCodeURLOption       = WithURLParams(nil)
	_ AuthCodeExchangeOption  = WithURLParams(nil)
	_ ClientCredentialsOption = WithURLParams(nil)
	_ TokenExchangeOption     = WithURLParams(nil)
)

func (wup WithURLParams) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	for k, v := range wup {
		target.AuthCodeOptions = append(target.AuthCodeOptions, oauth2.SetAuthURLParam(k, v))
	}
}

func (wup WithURLParams) ApplyToAuthCodeExchangeOptions(target *AuthCodeExchangeOptions) {
	for k, v := range wup {
		target.AuthCodeOptions = append(target.AuthCodeOptions, oauth2.SetAuthURLParam(k, v))
	}
}

func (wup WithURLParams) ApplyToClientCredentialsOptions(target *ClientCredentialsOptions) {
	if target.EndpointParams == nil {
		target.EndpointParams = make(url.Values, len(wup))
	}

	for k, v := range wup {
		target.EndpointParams.Set(k, v)
	}
}

func (wup WithURLParams) ApplyToTokenExchangeOptions(target *TokenExchangeOptions) {
	for k, v := range wup {
		target.AuthCodeOptions = append(target.AuthCodeOptions, oauth2.SetAuthURLParam(k, v))
	}
}

type WithProviderOptions map[string]string

var (
	_ AuthCodeURLOption        = WithProviderOptions(nil)
	_ DeviceCodeAuthOption     = WithProviderOptions(nil)
	_ DeviceCodeExchangeOption = WithProviderOptions(nil)
	_ AuthCodeExchangeOption   = WithProviderOptions(nil)
	_ RefreshTokenOption       = WithProviderOptions(nil)
	_ ClientCredentialsOption  = WithProviderOptions(nil)
	_ TokenExchangeOption      = WithProviderOptions(nil)
)

func (wpo WithProviderOptions) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToDeviceCodeAuthOptions(target *DeviceCodeAuthOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToDeviceCodeExchangeOptions(target *DeviceCodeExchangeOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToAuthCodeExchangeOptions(target *AuthCodeExchangeOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToRefreshTokenOptions(target *RefreshTokenOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToClientCredentialsOptions(target *ClientCredentialsOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToTokenExchangeOptions(target *TokenExchangeOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}
