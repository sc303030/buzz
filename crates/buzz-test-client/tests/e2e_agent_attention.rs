//! End-to-end tests for kind:30180 agent attention configuration (NIP-AT).
//!
//! The ingest and read-gate unit tests in `buzz-relay` pin the rules in
//! isolation. These tests prove the rules on the live relay paths:
//! - only the agent (`authors=[self]`) and the owner (`#p=[self]`) can read
//!   the kind, through `REQ` and `COUNT`;
//! - the relay refuses a malformed envelope;
//! - the NIP-AT reader subscription gets the stored policy, no stored
//!   deletions (`limit:0`), and then live kind:5 deletions from the agent and
//!   from the registered owner, including one whose `created_at` is earlier
//!   than the subscription;
//! - a fresh read after those deletions returns no deleted object.
//!
//! See `docs/nips/NIP-AT.md` for the contract.
//!
//! # Running
//!
//! Start the relay, then run:
//!
//! ```text
//! RELAY_URL=ws://localhost:3000 cargo test -p buzz-test-client --test e2e_agent_attention -- --ignored
//! ```

use std::time::Duration;

use buzz_sdk::nip_oa;
use buzz_test_client::{BuzzTestClient, RelayMessage};
use nostr::nips::nip44;
use nostr::{Alphabet, EventBuilder, Filter, Keys, Kind, SingleLetterTag, Tag, Timestamp};
use sha2::{Digest, Sha256};

const ATTENTION_KIND: u16 = 30180;

fn relay_url() -> String {
    std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3000".to_string())
}

fn sub_id(name: &str) -> String {
    format!("e2e-attention-{name}-{}", uuid::Uuid::new_v4())
}

/// A unique 64-lowercase-hex `d` tag. Real writers use an HMAC over the
/// conversation key; the relay checks only the shape.
fn unique_d() -> String {
    hex::encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()))
}

fn now() -> u64 {
    Timestamp::now().as_secs()
}

fn attention_event(agent: &Keys, owner: &Keys, d_tag: &str, created_at: u64) -> nostr::Event {
    let body = r#"{"schema":"agent-attention/v1","slug":"watch/e2e","seq":1,"value":{}}"#;
    let content = nip44::encrypt(
        agent.secret_key(),
        &owner.public_key(),
        body,
        nip44::Version::V2,
    )
    .expect("nip44 encrypt");
    EventBuilder::new(Kind::Custom(ATTENTION_KIND), content)
        .tags(vec![
            Tag::parse(["d", d_tag]).unwrap(),
            Tag::parse(["p", owner.public_key().to_hex().as_str()]).unwrap(),
            Tag::parse(["alt", "encrypted agent attention configuration"]).unwrap(),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(agent)
        .unwrap()
}

fn attention_delete(signer: &Keys, agent: &Keys, d_tag: &str, created_at: u64) -> nostr::Event {
    let coord = format!("{ATTENTION_KIND}:{}:{d_tag}", agent.public_key().to_hex());
    EventBuilder::new(Kind::Custom(5), "")
        .tags(vec![
            Tag::parse(["a", coord.as_str()]).unwrap(),
            Tag::parse(["k", ATTENTION_KIND.to_string().as_str()]).unwrap(),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(signer)
        .unwrap()
}

/// Connect the agent with a NIP-OA owner attestation so the relay registers
/// `owner` as the agent's owner (required for owner-signed deletions).
async fn connect_agent_with_owner(agent: &Keys, owner: &Keys) -> BuzzTestClient {
    let tag_json = nip_oa::compute_auth_tag(owner, &agent.public_key(), "kind=9")
        .expect("compute NIP-OA auth tag");
    let auth_tag = nip_oa::parse_auth_tag(&tag_json).expect("parse NIP-OA auth tag");
    let mut client = BuzzTestClient::connect_unauthenticated(&relay_url())
        .await
        .expect("connect agent unauthenticated");
    client
        .authenticate_with_nip_oa(agent, &auth_tag)
        .await
        .expect("authenticate agent with NIP-OA owner");
    client
}

fn by_author(agent: &Keys) -> Filter {
    Filter::new()
        .kind(Kind::Custom(ATTENTION_KIND))
        .author(agent.public_key())
}

fn by_owner(owner: &Keys) -> Filter {
    Filter::new()
        .kind(Kind::Custom(ATTENTION_KIND))
        .custom_tags(
            SingleLetterTag::lowercase(Alphabet::P),
            [owner.public_key().to_hex()],
        )
}

/// The NIP-AT reader subscription: stored config plus live-only deletions.
fn reader_filters(agent: &Keys, owner: &Keys) -> Vec<Filter> {
    vec![
        by_author(agent).limit(1000),
        Filter::new()
            .kind(Kind::Custom(5))
            .authors([agent.public_key(), owner.public_key()])
            .custom_tags(
                SingleLetterTag::lowercase(Alphabet::K),
                [ATTENTION_KIND.to_string()],
            )
            .limit(0),
    ]
}

async fn query(client: &mut BuzzTestClient, name: &str, filter: Filter) -> Vec<nostr::Event> {
    let sid = sub_id(name);
    client
        .subscribe(&sid, vec![filter])
        .await
        .expect("subscribe");
    client
        .collect_until_eose(&sid, Duration::from_secs(5))
        .await
        .expect("collect events")
}

/// Expect the relay to answer `sub_id` with CLOSED `restricted: ...`.
async fn expect_restricted(client: &mut BuzzTestClient, sid: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match client.recv_event(remaining).await.expect("relay reply") {
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id == sid => {
                assert!(message.starts_with("restricted:"), "got: {message}");
                return;
            }
            RelayMessage::Event {
                subscription_id, ..
            } if subscription_id == sid => panic!("non-owner read returned an event"),
            RelayMessage::Eose { subscription_id } if subscription_id == sid => {
                panic!("non-owner read was answered instead of refused")
            }
            _ => {}
        }
    }
}

/// Wait for a live event on `sid` and return it.
async fn next_live(client: &mut BuzzTestClient, sid: &str) -> nostr::Event {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match client.recv_event(remaining).await.expect("live event") {
            RelayMessage::Event {
                subscription_id,
                event,
            } if subscription_id == sid => return *event,
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id == sid => panic!("reader subscription closed: {message}"),
            _ => {}
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_attention_reads_are_limited_to_agent_and_owner() {
    let agent = Keys::generate();
    let owner = Keys::generate();
    let stranger = Keys::generate();
    let d_tag = unique_d();

    let mut agent_client = connect_agent_with_owner(&agent, &owner).await;
    let ok = agent_client
        .send_event(attention_event(&agent, &owner, &d_tag, now()))
        .await
        .expect("send config");
    assert!(ok.accepted, "relay rejected config event: {}", ok.message);

    assert_eq!(
        query(&mut agent_client, "agent", by_author(&agent))
            .await
            .len(),
        1
    );

    let mut owner_client = BuzzTestClient::connect(&relay_url(), &owner)
        .await
        .expect("connect owner");
    assert_eq!(
        query(&mut owner_client, "owner", by_owner(&owner))
            .await
            .len(),
        1
    );

    let mut stranger_client = BuzzTestClient::connect(&relay_url(), &stranger)
        .await
        .expect("connect stranger");
    for (name, filter) in [
        ("stranger-author", by_author(&agent)),
        ("stranger-p", by_owner(&owner)),
        (
            "stranger-bare",
            Filter::new().kind(Kind::Custom(ATTENTION_KIND)),
        ),
    ] {
        let sid = sub_id(name);
        stranger_client
            .subscribe(&sid, vec![filter])
            .await
            .expect("subscribe");
        expect_restricted(&mut stranger_client, &sid).await;
    }

    let sid = sub_id("stranger-count");
    stranger_client
        .send_raw(&serde_json::json!(["COUNT", sid, by_author(&agent)]))
        .await
        .expect("send COUNT");
    expect_restricted(&mut stranger_client, &sid).await;

    agent_client.disconnect().await.expect("disconnect agent");
    owner_client.disconnect().await.expect("disconnect owner");
    stranger_client
        .disconnect()
        .await
        .expect("disconnect stranger");
}

#[tokio::test]
#[ignore]
async fn test_attention_rejects_malformed_envelope() {
    let agent = Keys::generate();
    let mut client = BuzzTestClient::connect(&relay_url(), &agent)
        .await
        .expect("connect");

    let no_owner = EventBuilder::new(
        Kind::Custom(ATTENTION_KIND),
        "Ag".to_string() + &"A".repeat(130),
    )
    .tags(vec![Tag::parse(["d", unique_d().as_str()]).unwrap()])
    .sign_with_keys(&agent)
    .unwrap();
    let ok = client.send_event(no_owner).await.expect("send");
    assert!(
        !ok.accepted,
        "relay accepted a config event without an owner"
    );
    assert!(
        ok.message.contains("agent-attention"),
        "got: {}",
        ok.message
    );

    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn test_attention_reader_receives_live_deletions_from_agent_and_owner() {
    let agent = Keys::generate();
    let owner = Keys::generate();
    let kept = unique_d();
    let by_agent = unique_d();
    let by_owner_skewed = unique_d();
    let already_gone = unique_d();
    let t = now();

    let mut agent_client = connect_agent_with_owner(&agent, &owner).await;
    // `by_owner_skewed` is old so that its deletion can also be old.
    for (d, at) in [
        (&kept, t),
        (&by_agent, t),
        (&by_owner_skewed, t - 300),
        (&already_gone, t),
    ] {
        let ok = agent_client
            .send_event(attention_event(&agent, &owner, d, at))
            .await
            .expect("send config");
        assert!(ok.accepted, "relay rejected config event: {}", ok.message);
    }
    // A deletion stored before the reader subscribes must not be replayed.
    let ok = agent_client
        .send_event(attention_delete(&agent, &agent, &already_gone, t))
        .await
        .expect("send early delete");
    assert!(ok.accepted, "relay rejected early delete: {}", ok.message);

    let mut reader = BuzzTestClient::connect(&relay_url(), &agent)
        .await
        .expect("connect reader");
    let sid = sub_id("reader");
    reader
        .subscribe(&sid, reader_filters(&agent, &owner))
        .await
        .expect("subscribe reader");
    let snapshot = reader
        .collect_until_eose(&sid, Duration::from_secs(5))
        .await
        .expect("reader snapshot");
    let mut kinds: Vec<u16> = snapshot.iter().map(|e| e.kind.as_u16()).collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        vec![ATTENTION_KIND; 3],
        "snapshot must hold the three live objects and no stored deletion"
    );

    let agent_delete = attention_delete(&agent, &agent, &by_agent, t + 1);
    let ok = agent_client
        .send_event(agent_delete.clone())
        .await
        .expect("send agent delete");
    assert!(ok.accepted, "relay rejected agent delete: {}", ok.message);
    assert_eq!(next_live(&mut reader, &sid).await.id, agent_delete.id);

    // Signed earlier than the subscription opened (clock skew) — still live.
    let owner_delete = attention_delete(&owner, &agent, &by_owner_skewed, t - 120);
    let mut owner_client = BuzzTestClient::connect(&relay_url(), &owner)
        .await
        .expect("connect owner");
    let ok = owner_client
        .send_event(owner_delete.clone())
        .await
        .expect("send owner delete");
    assert!(ok.accepted, "relay rejected owner delete: {}", ok.message);
    assert_eq!(next_live(&mut reader, &sid).await.id, owner_delete.id);

    let fresh = query(&mut reader, "fresh", by_author(&agent)).await;
    let d_tags: Vec<String> = fresh
        .iter()
        .filter_map(|e| e.tags.identifier().map(str::to_string))
        .collect();
    assert_eq!(
        d_tags,
        vec![kept.clone()],
        "fresh read must hold only the kept object"
    );

    reader.disconnect().await.expect("disconnect reader");
    agent_client.disconnect().await.expect("disconnect agent");
    owner_client.disconnect().await.expect("disconnect owner");
}
