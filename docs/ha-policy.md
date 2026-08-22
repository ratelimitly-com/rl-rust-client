# High-availability resource-request policy

An API key may use more than one Ratelimitly server. The client sends each
resource request according to one configurable policy and selects one valid
response for the application.

This policy changes delivery and response selection. It does not change the
atomic meaning of a resource request.

## Membership and preference

Each resource request uses a snapshot of the servers known when it begins. The
client gives the oldest server the highest preference during the initial
round. Discovery changes apply only to later requests.

## Policy parameters

| Parameter | Symbol | Meaning |
| --- | --- | --- |
| time unit | `U` | Base duration used by every round. |
| replay count | `N` | Replays after the initial send. |
| replay-gap schedule | `B(k)` | Duration of transmission round `k`, in units of `U`. |
| final receive units | `F` | Receive-only duration after all transmission rounds. Zero removes this phase. |
| completion delivery | — | Before returning a decision, make one best-effort delivery to servers that have not responded. |

The replay-gap schedule may be fixed, linearly increasing, or exponentially
increasing, with a configured upper bound. Round zero is the initial
transmission; rounds `1..=N` are replay rounds.

The complete request horizon is:

```text
H = U × (B(0) + B(1) + ... + B(N) + F)
```

The client uses `H` as the deduplication lifetime for the request. It rejects a
policy whose horizon exceeds the limit carried by the API key. All sends for
one logical request remain part of that same request.

## Selection algorithm

For one non-empty resource request:

1. Send the request to every server in the request's membership snapshot.
2. During the initial round:
   - return immediately when the oldest server supplies a valid response;
   - otherwise retain the response from the oldest responder seen so far;
   - at the round deadline, return that retained response if one exists.
3. If the initial round was silent, start each configured replay round by
   sending to servers that have not responded. In a replay round, the first
   valid response completes the request.
4. If every transmission round was silent and `F > 0`, wait without sending for
   `F × U`. The first valid response completes the request.
5. If the final deadline is silent, return a timeout failure.

Once a response is selected, a later response cannot change the application's
result. Grants and rejections use the same selection rules.

## Completion delivery

When completion delivery is enabled, the client makes one best-effort delivery
to every server that has not supplied a valid response before it returns the
selected decision. It does not wait for more responses and does not change the
selected result if that delivery fails. The client never starts completion
delivery at or after the request's deduplication deadline; a policy with no
remaining horizon at selection time therefore cannot make that extra send.

Completion delivery applies to both grants and rejections. Sending the same
logical request to missing servers helps keep future decisions consistent
across the available service. Disable it when the application prefers fewer
sends over that convergence behavior.

## Default policy

The default policy is:

| Parameter | Default |
| --- | ---: |
| `U` | 20 ms |
| `N` | 1 replay |
| `B(0)`, `B(1)` | 1 unit, fixed |
| `F` | 1 unit |
| completion delivery | enabled |
| `H` | 60 ms |

The sequence is:

1. send to all servers and apply oldest-server preference for up to 20 ms;
2. if silent, replay to servers that have not responded and accept the first
   valid response for up to 20 ms;
3. if still silent, wait without sending and accept the first valid response
   for up to 20 ms; and
4. otherwise return a timeout.

The final receive phase is optional. Setting `F = 0` removes it and shortens the
request horizon.

## Tuning

Choose `U` from measured request round-trip times for the application's normal
deployment regions. Increasing replays or round lengths can tolerate more loss
and slow responses, but increases the maximum decision latency. Every policy
must remain within the API key's limit.

## Latency reports

Latency reports use a separate delivery contract. A report is sent once to the
currently available Ratelimitly servers and does not use resource-request
replays, response selection, or the final receive phase.

## Canonical specifications

This guide explains the Rust-facing configuration of the agreed client
strategy. The canonical protocol vocabulary and server-facing message
semantics are defined by the
[wire protocol](https://github.com/ratelimitly-com/rl/blob/main/docs/spec/wire_protocol.md).
The complete language-independent client strategy, including membership,
selection, retry, and convergence assumptions, is defined by the
[r-client specification](https://github.com/ratelimitly-com/rl/blob/main/docs/spec/r-client.md).

Those specifications are normative. This guide deliberately does not duplicate
wire layouts or make the HA policy a server requirement.
