NIP-AT
======

Agent Attention Configuration
-----------------------------

`draft` `optional`

This NIP defines how an AI agent stores its attention policy on a relay. The policy is the set of objects that decide which events wake the agent: **Interests**, **watches** and **timers**. Each object is one addressable `kind:30180` event ([NIP-01](01.md)), signed by the agent and encrypted with [NIP-44](44.md) to the conversation key between the agent and its owner. Only the agent and the owner can read it.

The envelope is the same as [NIP-AE](NIP-AE.md) engrams. Only the kind, the HMAC domain and the body differ. The kind is separate so that runtimes that apply a policy do not mix it with agent memory.

## Roles

- **agent** — the identity (`pubkey_a`) that signs every config event.
- **owner** — the identity (`pubkey_o`) named in the single `p` tag.

## Event

```
K_c  = nip44_conversation_key(seckey_agent, pubkey_owner)
d(x) = lower_hex(HMAC-SHA256(K_c, "agent-attention/v1/d-tag" || 0x00 || x))
```

```jsonc
{
  "kind": 30180,
  "pubkey": "<agent>",
  "tags": [
    ["d", "<d(slug)>"],
    ["p", "<owner>"],
    ["alt", "encrypted agent attention configuration"]
  ],
  "content": "<nip44(K_c, body)>"
}
```

The decrypted body is a JSON object:

```jsonc
{ "schema": "agent-attention/v1", "slug": "watch/project-messages", "seq": 12, "value": { } }
```

- `slug` is `interest/<id>` or `watch/<id>`. Watches and timers share the `watch/` space; `value` says which type it is. IDs match `^[!-~]{1,64}$`.
- `seq` orders objects. Readers sort by `seq`, then by `slug`.
- `value` is the runtime's normalized object. Its fields are defined by the runtime, not by this NIP.
- A reader MUST check that `d(slug)` equals the event's `d` tag and MUST ignore the event if it does not.

## Relay behavior

A relay that supports this NIP:

- MUST accept `kind:30180` only with exactly one `d` tag (64 lowercase hex), exactly one `p` tag (64 lowercase hex) and NIP-44 v2 content.
- MUST store it as a global (non-channel) addressable event.
- MUST answer a filter that can match `kind:30180` only when `authors` contains only the authenticated pubkey, or `#p` contains only the authenticated pubkey. Filters with explicit `ids` are exempt. This applies to `REQ`, `COUNT` and search.

## Removal

An object is removed with a [NIP-09](09.md) `kind:5` event with one `a` tag, `30180:<agent>:<d>`, and a `["k", "30180"]` tag. The agent or its registered owner may sign it. A deletion removes only versions with `created_at` at or before its own.

The deletion event is not encrypted. It shows the agent key, the time, the kind and the hashed `d` tag. It does not show the owner, the slug or the content.

## Reading

A reader opens one subscription:

```
[ { "kinds": [30180], "authors": ["<agent>"], "limit": 1000 },
  { "kinds": [5], "authors": ["<agent>", "<owner>"], "#k": ["30180"], "limit": 0 } ]
```

The first filter returns the stored policy and then live changes. The second returns no stored events and delivers live deletions. For each address the reader keeps the event with the newest `created_at`, and on a tie the lowest event ID. A deletion removes an object whose `created_at` is at or before the deletion's. On reconnect the reader replaces its whole policy with the new result.

If a page holds as many events as the relay's page limit, the reader requests the next page with `until` set to the oldest `created_at` in the page, and stops when a page is not full.
