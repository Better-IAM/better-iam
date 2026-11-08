# better-iam-a2a

Agent2Agent (A2A) support for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of
the `@better-iam/a2a` npm package:

- `verify_agent_card` and `discover_agent`: verify agent cards a Better IAM deployment attested (`agents.signCard`)
  with its published keys, and fetch and verify a remote agent's card;
- `create_card_attestor`: keep an agent's own card signed, re-signing before the attestation ends;
- `verify_delegation_token` and `create_delegation_token_cache`: check, offline, a delegation token an agent presents
  for a person, and cache tokens on the agent side;
- `create_a2a_gate` and `create_a2a_authorizer`: authorization for A2A servers speaking JSON-RPC over HTTP (skills,
  private tasks and conversations, filtered extended cards, confirmations by the person an agent acts for).

With the default `server` feature, an in-process `BetterIam` (`better_iam(options)`) is an `A2aIam`.
