package main

import "github.com/a2aproject/a2a-go/v2/a2asrv/push"

// referencePushSender permits the trusted local TCK webhook receiver. This
// reference server itself listens only on loopback; production agents should
// retain the SDK default SSRF guard unless their callback network is trusted.
// Authentication, StreamResponse encoding, delivery, and redirect credential
// stripping remain implemented by the SDK sender.
func referencePushSender() *push.HTTPPushSender {
	return push.NewHTTPPushSender(&push.HTTPSenderConfig{AllowPrivateNetworks: true})
}
