package adapters

import "github.com/gabbykarry/namd/internal/webhook"

// Registry returns all available adapters as a map.
// The key is the adapter name used in namd.yml (adapter: "paystack").
// The value is the concrete adapter implementation.
//
// TO ADD A NEW ADAPTER:
//  1. Create a new file e.g. stripe.go in this package
//  2. Implement the webhook.Adapter interface (Name, Verify, Normalize)
//  3. Add one line here: "stripe": &StripeAdapter{}
//  4. Open a PR — nothing else needs to change
//
// The engine never imports specific adapters.
// It only receives this map and calls through the Adapter interface.
// This is the Open/Closed principle: open for extension, closed for modification.
func Registry() map[string]webhook.Adapter {
	return map[string]webhook.Adapter{
		"generic":     &GenericAdapter{},
		"paystack":    &PaystackAdapter{},
		"flutterwave": &FlutterwaveAdapter{},
		"github":      &GitHubAdapter{},
	}
}
