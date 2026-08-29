# Configuration and API-key handling

The client takes one API key and derives the associated Ratelimitly
configuration from it. Callers do not repeat credential fields that could
disagree with one another.

## Create a client

```rust
use ratelimitly::{ApiKey, Client};

let api_key: ApiKey = std::env::var("RATELIMITLY_API_KEY")?.parse()?;
let client = Client::builder(api_key).build().await?;
```

`ApiKey` validates the credential before use and redacts it from formatted
output. Invalid or unsupported keys fail during configuration.

## Handle API keys safely

An API key is a credential:

- load it through a secret manager or protected environment variable;
- do not commit it or embed it in examples;
- do not pass it as a command-line argument;
- do not include it in errors, tracing, telemetry, or debug output; and
- rotate it if it may have been exposed.

Treat `ApiKey` as an opaque credential.

## Service discovery

Normal clients need no discovery configuration. The API key identifies the
Ratelimitly service to use, and the client discovers its available servers.
Discovery results are reused across operations and refreshed over time.

Development or staging environments may supply an explicit service domain:

```rust
let client = Client::builder(api_key)
    .service_domain("test.ratelimitly.invalid")?
    .build()
    .await?;
```

An override changes only service discovery. It does not override the identity
or limits carried by the API key. Use an override only with a domain configured
for Ratelimitly service discovery.

Deterministic tests or controlled development environments may also direct
queries to one explicit DNS server:

```rust
use std::net::SocketAddr;

let dns_server: SocketAddr = "127.0.0.1:5300".parse()?;
let client = Client::builder(api_key)
    .service_domain("test.ratelimitly.invalid")?
    .dns_server(dns_server)
    .build()
    .await?;
```

This bypasses the operating-system resolver. It is not a server endpoint and
does not change the API-key identity, quotas, or authentication method.

Each resource request uses a stable snapshot of the currently discovered
servers. A refresh affects later requests, not a request already in progress.
If no service is available, the operation returns a discovery error rather
than inventing a fallback endpoint.

## Source-port steering

An r-server response may advise the client either to keep its current UDP
source port or to use a different one for future sends. This flag is a
transport optimization, not part of the grant or rejection decision, and the
client decides when it is safe to act on it.

When requests are concurrent, they continue receiving on the socket from which
they were sent. The client coalesces switch-port advice and changes the shared
socket only after those active requests drain. The new source port therefore
applies to later transmissions without invalidating responses already in
flight. Rebinding also preserves the socket's IPv4 or IPv6 address family; an
occupied candidate port makes the client try another port in that same family.
Candidate ports advance monotonically through the dynamic-port range, skipping
ports that cannot be acquired, so steering does not revisit a prior port until
the complete range has been traversed. On Windows, replacement sockets claim
their port exclusively so a wildcard client socket cannot silently share a
port with a socket bound to a specific local address.
Before steering completes, the response router confirms that it is receiving
from the replacement socket, so a fast response to the next request is not
lost during the transition.

## Request policy

Resource-request delivery is controlled by one parameterized policy rather
than separate named modes:

```rust
use std::time::Duration;
use ratelimitly::{RequestPolicy, Schedule};

let policy = RequestPolicy::builder()
    .unit(Duration::from_millis(20))
    .replays(1)
    .replay_gap(Schedule::fixed(1))
    .final_receive_units(1)
    .completion_delivery(true)
    .build()?;

let client = Client::builder(api_key)
    .request_policy(policy)
    .build()
    .await?;
```

The client validates the complete schedule against the API key before sending
a request. See [High-availability request policy](ha-policy.md) for the timing
model and defaults.

## Resource and tracker limits

The client validates resource windows and the request-policy horizon against the
API key. Invalid configuration fails before the request is sent. Tracker storage
capacity is allocated and enforced server-side based on the tenant's API key.

## Runtime and lifecycle

The client is asynchronous and uses Tokio. Construct it once and reuse it so
discovery information and communication resources persist across operations.
Dropping the client releases its resources.
