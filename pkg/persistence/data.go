package persistence

import (
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
)

type Holder struct {
	Config      *ConfigHolder
	AuthCode    *AuthCodeHolder
	AuthServer  *AuthServerHolder
	ClientCreds *ClientCredsHolder
}

func NewHolder() *Holder {
	return &Holder{
		Config:      &ConfigHolder{locks: locksutil.CreateLocks()},
		AuthCode:    &AuthCodeHolder{locks: locksutil.CreateLocks()},
		AuthServer:  &AuthServerHolder{locks: locksutil.CreateLocks()},
		ClientCreds: &ClientCredsHolder{locks: locksutil.CreateLocks()},
	}
}
