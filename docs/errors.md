# Decisions, failures, and application policy

The client keeps valid Ratelimitly decisions separate from failures to obtain a
decision. Applications must preserve this distinction.

## Outcome model

```text
resource request
    |
    +-- Ok(Granted)  -> resources consumed; protected work may begin
    |
    +-- Ok(Rejected) -> nothing consumed; protected work must not begin
    |
    `-- Err(Failure) -> no decision; application policy decides
```

The Rust API represents grant and rejection with `Decision` and operational
failure with `Result::Err`. An empty resource request is a local grant and does
not contact Ratelimitly.

## Failure categories

| Category | Meaning |
| --- | --- |
| configuration | The API key, request, tracker, or policy is invalid. |
| discovery | No Ratelimitly service is currently available. |
| communication | The client could not send or receive as required. |
| timeout | No valid decision arrived before the request horizon ended. |

Errors and diagnostic output must never contain the API key.

## A timeout is not a rejection

A timeout means that the client did not receive a usable decision in time. It
can result from connectivity, service availability, or a lost response.

A timeout also does not prove that Ratelimitly did not process the request. The
request may have arrived while its response did not. Do not automatically
create a new logical request after a timeout unless the application accepts
that uncertainty.

## Communication failures can be partial

When an operation targets more than one server, a communication failure may
occur after another server received the operation. The same uncertainty applies
to resource requests, completion delivery, and latency reports.

Completion delivery is best effort after a decision has already been selected.
Its failure does not turn a valid grant or rejection into an application
failure. A communication failure before a decision is available instead ends
the request with an error.

## Application failure policy

The library does not choose fail-open or fail-closed behavior. That decision
depends on the protected operation:

- **fail closed** protects resource limits but may reduce availability;
- **fail open** preserves availability but may exceed limits; and
- a **fallback** may use a local limiter, queue, cached policy, or degraded
  service behavior.

Make the policy explicit at the integration boundary and observe each outcome
separately. Do not report a failure as a Ratelimitly rejection, and do not count
an application fail-open as a Ratelimitly grant.

## Latency-report failures

A latency report makes no admission decision. A report failure should normally
be treated as measurement-delivery failure, not as a reason to change an
already completed application response.
