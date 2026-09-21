package gate

import "crypto/rand"

// randReader is the randomness the idempotency key's suffix comes from.
var randReader = rand.Reader
