package router

import "github.com/v2fly/v2ray-core/v5/app/router/userpolicy"

type (
	UserPolicy        = userpolicy.Policy
	UserRoutingPolicy = userpolicy.Policy
	UserPolicyConfig  = userpolicy.Config
	UserPolicyTable   = userpolicy.Table
)

var NewUserPolicyTable = userpolicy.NewTable
