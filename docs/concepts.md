# Concepts and operation model

This guide explains the operations exposed by the Rust client. Configuration,
delivery policy, and failure handling are covered separately.

## Resource requests are atomic admission decisions

A resource request contains two independent collections:

- **resource consumptions**: named rate counters and the quantities the
  application intends to consume; and
- **latency guards**: named latency trackers and thresholds that must pass
  before the work may begin.

Both collections may be empty. Every non-empty request is evaluated as one
atomic operation:

- **grant** means every guard passed and every requested quantity was consumed;
- **rejection** means at least one condition failed and no requested quantity
  was consumed.

Send a resource request only after the application's other admission checks
have passed, and perform the protected work after a grant. A grant represents
consumption of the resource; it is not a probe.

An empty request is the identity case. It grants locally without contacting
Ratelimitly. A guard-only request is not empty and is evaluated normally.

## Resources are content-defined

A rate counter is identified by all values that define it:

- the application-defined resource name;
- the rate-counter window; and
- the rate limit.

Changing the name, window, or rate intentionally identifies a different
counter. Independently deployed clients agree on a counter when they use
exactly the same definition.

Names are case-sensitive and byte-sensitive. Treat resource definitions as
shared configuration rather than constructing them differently in each
service.

## Latency trackers are content-defined

A latency tracker is identified by:

- the application-defined tracker name;
- sample lifetime;
- maximum samples;
- buffer size; and
- minimum sample threshold.

Changing any of those values intentionally creates a different tracker. A
guard threshold is not part of the tracker identity: different guards may
apply different thresholds to the same observations.

| Setting | Meaning |
| --- | --- |
| sample lifetime | Maximum age of an observation used by the tracker. |
| maximum samples | Maximum number of recent observations considered. |
| buffer size | Requested tracker storage, bounded by the API key. |
| minimum samples | Warm-up population required before latency controls admission. |

Use the same tracker definition everywhere that reads or reports that tracker.
The same name with different settings identifies different trackers.

## Latency reports are independent observations

A latency report adds one measured duration to a tracker. It does not consume a
resource or request an admission decision.

A common application workflow is:

1. ask for admission with a guard;
2. perform the work only after a grant;
3. measure the work with a monotonic clock; and
4. optionally report the duration to the same tracker.

That workflow is not a pairing rule. A dedicated observer may report
measurements produced elsewhere, and a resource consumer may never report.
Never fabricate a latency for work that did not execute.

## Detailed decision results

A resource-request response contains the combined decision and may also expose
the individual resource and guard results. Use resource and tracker identities
when inspecting those details.

A zero token deficit means the requested resource quantity was available. A
nonzero deficit is the quantity that could not be supplied. A guard passes only
when the tracked latency is below its threshold. The combined decision is
granted only when every condition passes.

## API-key limits

An API key defines limits for resource windows, latency-tracker storage,
request timing, and the number of distinct resources, trackers, and metrics
labels. These limits protect both the account and the service.

The client validates limits that can be checked before sending and returns a
configuration error when a request or policy exceeds them. Ratelimitly applies
the remaining limits. Limits are not defaults: resource and tracker definitions
remain explicit application configuration.

## Metrics labels

A resource request may carry an optional metrics label for grouping API-key
metrics. The label does not affect resource identity, tracker identity, or the
grant/rejection decision. Keep label cardinality bounded and use stable values
rather than request-specific identifiers.
