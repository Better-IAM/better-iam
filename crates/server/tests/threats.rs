//! The threats module's catalog, settings, and risk arithmetic (threats.ts): the parts of tests/threats-api.test.ts,
//! tests/threats-engine.test.ts and tests/threat-rules.test.ts that reach `threatRules`, `resolveThreatSettings`,
//! `riskScore`, `effectiveRisk`, `riskContext` and `endContainment`, called directly where the TypeScript tests go
//! through the `threats` API group and the detection engine (ported in their own units).

mod organization_fixture;

use better_iam_core::{IamStoreExt, Identity, PolicyDocument};
use better_iam_server::threats::{
    IdentityRisk, RiskContribution, ThreatSettings, effective_risk, end_containment, max_severity,
    mentions_risk, resolve_threat_settings, risk_context, risk_level_at_least, risk_score,
    severity_at_least, threat_rule, threat_rule_ids, threat_rules,
};
use organization_fixture::{assert_matches, organization, run};
use serde_json::{Map, Value, json};

const HOUR: f64 = 3_600_000.0;

fn contribution(points: f64, at: f64) -> RiskContribution {
    RiskContribution {
        detection_id: "d1".into(),
        rule_id: json!("user-reported"),
        severity: json!("high"),
        points,
        at,
        extra: Map::new(),
    }
}

fn risk(contributions: Vec<RiskContribution>, over: Option<Value>) -> IdentityRisk {
    IdentityRisk {
        identity_id: "i1".into(),
        contributions,
        score: 0.0,
        level: json!("none"),
        r#override: over,
        contained: None,
        updated_at: 0.0,
        id: "i1".into(),
        tenant_id: "t1".into(),
        unique_key: None,
        extra: Map::new(),
    }
}

#[test]
fn catalog_lists_every_rule_in_display_order() {
    let rules = threat_rules().unwrap();
    assert_eq!(rules.len(), 22);
    assert_eq!(rules[0].id, json!("password-spray"));
    assert_eq!(rules[21].id, json!("upstream-signal"));
    assert!(rules.iter().all(|rule| rule.enabled_by_default));
    assert_eq!(threat_rule_ids().unwrap().len(), 22);
    let spray = serde_json::to_value(threat_rule(&json!("password-spray")).unwrap()).unwrap();
    assert_matches(
        &spray,
        json!({
            "id": "password-spray",
            "category": "sign-in",
            "severity": "high",
            "subject": "network",
            "threshold": 10,
            "windowMs": 900_000,
            "tunable": { "threshold": [3, 1000], "windowMs": [60_000, 86_400_000] },
            "enabledByDefault": true,
            "technique": "T1110.003",
        }),
    );
    let persistence = threat_rule(&json!("account-takeover-persistence")).unwrap();
    assert_eq!(persistence.threshold, None);
    assert_eq!(persistence.window_ms, Some(HOUR));
    assert_eq!(
        persistence.tunable,
        Some(json!({ "windowMs": [300_000, 604_800_000] }))
    );
    assert_eq!(threat_rule(&json!("session-hijack")).unwrap().tunable, None);
    let unknown = threat_rule(&json!("nope")).unwrap_err();
    assert_eq!(
        (unknown.code.as_str(), unknown.status),
        ("INTERNAL_ERROR", 500)
    );
}

#[test]
fn settings_resolve_rule_and_deployment_defaults() {
    let defaults = resolve_threat_settings(None).unwrap();
    assert_eq!(defaults.dormant_days, 90.0);
    assert_eq!(defaults.risk_half_life_hours, 24.0);
    assert_eq!(defaults.max_automatic_containments, 3.0);
    assert!(defaults.trusted_networks.is_empty());
    assert_eq!(defaults.notify, json!({ "owners": false, "emails": [] }));
    assert_eq!(defaults.rules.as_object().unwrap().len(), 22);
    assert_eq!(
        defaults.rules["brute-force"],
        json!({ "enabled": true, "severity": "medium", "threshold": 10, "windowMs": 900_000 })
    );
    // Rules that neither count nor correlate over time have no threshold or window to resolve.
    assert_eq!(
        defaults.rules["new-network"],
        json!({ "enabled": true, "severity": "medium" })
    );

    let stored: ThreatSettings = serde_json::from_value(json!({
        "id": "t1",
        "tenantId": "t1",
        "rules": {
            "brute-force": { "enabled": false, "threshold": 20 },
            "new-network": { "everyone": true },
            "audit-tampering": { "severity": "high" },
        },
        "trustedNetworks": ["10.0.0.0/8"],
        "dormantDays": 30,
        "riskHalfLifeHours": 12,
        "notify": { "owners": true, "emails": ["soc@example.test"] },
        "maxAutomaticContainments": 5,
        "updatedAt": 1,
        "updatedBy": "owner",
    }))
    .unwrap();
    let resolved = resolve_threat_settings(Some(&stored)).unwrap();
    let brute_force = &resolved.rules["brute-force"];
    assert_eq!(
        brute_force,
        &json!({ "enabled": false, "threshold": 20, "severity": "medium", "windowMs": 900_000 })
    );
    // The tenant's own members come first, as `{ ...own, enabled, severity, ... }` writes them.
    assert_eq!(
        brute_force
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        ["enabled", "threshold", "severity", "windowMs"]
    );
    assert_eq!(
        resolved.rules["new-network"],
        json!({ "everyone": true, "enabled": true, "severity": "medium" })
    );
    assert_eq!(resolved.rules["audit-tampering"]["severity"], json!("high"));
    assert_eq!(resolved.trusted_networks, ["10.0.0.0/8"]);
    assert_eq!(resolved.dormant_days, 30.0);
    assert_eq!(resolved.risk_half_life_hours, 12.0);
    assert_eq!(resolved.max_automatic_containments, 5.0);
    assert_eq!(
        resolved.notify,
        json!({ "owners": true, "emails": ["soc@example.test"] })
    );
}

#[test]
fn risk_decays_with_the_half_life_and_caps_at_one_hundred() {
    let now = 1_000_000_000.0;
    assert_eq!(
        risk_score(&[contribution(50.0, now)], now, 24.0).unwrap(),
        50.0
    );
    assert_eq!(
        risk_score(&[contribution(50.0, now)], now + 24.0 * HOUR, 24.0).unwrap(),
        25.0
    );
    assert_eq!(
        risk_score(
            &[contribution(80.0, now), contribution(80.0, now)],
            now,
            24.0
        )
        .unwrap(),
        100.0
    );
    // A half-life below one hour counts as one hour; contributions from the future count in full.
    assert_eq!(
        risk_score(&[contribution(50.0, now)], now + HOUR, 0.0).unwrap(),
        25.0
    );
    assert_eq!(
        risk_score(&[contribution(50.0, now + HOUR)], now, 24.0).unwrap(),
        50.0
    );
    // Math.round: halves round up.
    assert_eq!(
        risk_score(&[contribution(25.0, now)], now + 24.0 * HOUR, 24.0).unwrap(),
        13.0
    );
    assert_eq!(risk_score(&[], now, 24.0).unwrap(), 0.0);
}

#[test]
fn effective_risk_raises_to_an_unexpired_override() {
    let now = 1_000_000_000.0;
    assert_eq!(
        effective_risk(None, now, 24.0).unwrap(),
        json!({ "score": 0, "level": "none" })
    );
    let plain = risk(vec![contribution(25.0, now)], None);
    assert_eq!(
        effective_risk(Some(&plain), now, 24.0).unwrap(),
        json!({ "score": 25, "level": "low" })
    );
    let over = |expires_at: Option<f64>| {
        let mut value = json!({ "level": "high", "reason": "confirmed", "by": "o", "at": now });
        if let Some(expires_at) = expires_at {
            value["expiresAt"] = json!(expires_at);
        }
        risk(vec![contribution(25.0, now)], Some(value))
    };
    assert_eq!(
        effective_risk(Some(&over(None)), now, 24.0).unwrap(),
        json!({ "score": 70, "level": "high" })
    );
    assert_eq!(
        effective_risk(Some(&over(Some(now + HOUR))), now, 24.0).unwrap(),
        json!({ "score": 70, "level": "high" })
    );
    assert_eq!(
        effective_risk(Some(&over(Some(now))), now, 24.0).unwrap(),
        json!({ "score": 25, "level": "low" })
    );
    // An override never lowers a higher score's level.
    let low_floor = risk(
        vec![contribution(80.0, now)],
        Some(json!({ "level": "low", "reason": "r", "by": "o", "at": now })),
    );
    assert_eq!(
        effective_risk(Some(&low_floor), now, 24.0).unwrap(),
        json!({ "score": 80, "level": "high" })
    );
}

#[test]
fn severities_and_levels_compare_by_rank() {
    assert!(severity_at_least(&json!("high"), &json!("medium")).unwrap());
    assert!(severity_at_least(&json!("critical"), &json!("critical")).unwrap());
    assert!(!severity_at_least(&json!("low"), &json!("medium")).unwrap());
    assert!(!severity_at_least(&json!("high"), &json!("bogus")).unwrap());
    assert_eq!(
        max_severity(&json!("critical"), &json!("high")).unwrap(),
        json!("critical")
    );
    assert_eq!(
        max_severity(&json!("low"), &json!("medium")).unwrap(),
        json!("medium")
    );
    assert_eq!(
        max_severity(&json!("bogus"), &json!("low")).unwrap(),
        json!("low")
    );
    assert!(risk_level_at_least(&json!("high"), &json!("low")).unwrap());
    assert!(!risk_level_at_least(&json!("none"), &json!("low")).unwrap());
}

#[test]
fn documents_mention_risk_keys() {
    let document: PolicyDocument = serde_json::from_value(json!({
        "version": 1,
        "statements": [{
            "effect": "deny",
            "actions": ["*"],
            "resources": ["*"],
            "conditions": { "StringEquals": { "principal.riskLevel": "high" } },
        }],
    }))
    .unwrap();
    let plain: PolicyDocument = serde_json::from_value(json!({
        "version": 1,
        "statements": [{ "effect": "allow", "actions": ["*"], "resources": ["*"] }],
    }))
    .unwrap();
    assert!(mentions_risk(&[&plain, &document]));
    assert!(!mentions_risk(&[&plain]));
}

#[test]
fn risk_context_reads_the_person_and_the_agent() {
    run(|| async {
        let f = organization(|_| {}).await;
        let ctx = f.iam.ctx.clone();
        let alice = f.member("alice").await;
        let agent = f.member("agent").await;
        let now = f.now();
        f.insert(
            "identityRisk",
            json!({
                "id": alice, "tenantId": f.tenant_id, "identityId": alice,
                "contributions": [{ "detectionId": "d1", "ruleId": "brute-force", "severity": "medium", "points": 50, "at": now - 2.0 * HOUR }],
                "score": 50, "level": "medium", "updatedAt": now,
            }),
        )
        .await;
        // The tenant's half-life (one hour) decays the contribution: two hours later it counts a quarter.
        f.insert(
            "threatSettings",
            json!({
                "id": f.tenant_id, "tenantId": f.tenant_id, "rules": {}, "trustedNetworks": [],
                "dormantDays": 90, "riskHalfLifeHours": 1,
                "notify": { "owners": false, "emails": [] }, "maxAutomaticContainments": 3,
                "updatedAt": now, "updatedBy": f.owner_id,
            }),
        )
        .await;
        let credential = f.sign_in(&alice).await;
        let principal = ctx
            .principals()
            .unwrap()
            .authenticate(&credential)
            .await
            .unwrap();
        let store = f.store();
        let keys = risk_context(&store, &principal, now).await.unwrap();
        assert_eq!(
            Value::Object(keys),
            json!({ "principal.riskLevel": "low", "principal.riskScore": 13 })
        );

        // A delegated session takes the higher of the person's and the agent's risk.
        f.insert(
            "identityRisk",
            json!({
                "id": agent, "tenantId": f.tenant_id, "identityId": agent,
                "contributions": [], "score": 0, "level": "none",
                "override": { "level": "high", "reason": "r", "by": f.owner_id, "at": now },
                "updatedAt": now,
            }),
        )
        .await;
        let mut delegated = principal.clone();
        delegated.session.agent_id = Some(agent.clone());
        let keys = risk_context(&store, &delegated, now).await.unwrap();
        assert_eq!(
            Value::Object(keys),
            json!({ "principal.riskLevel": "high", "principal.riskScore": 70 })
        );

        // Simulated principals never carry risk.
        let identity: Identity = better_iam_server::port::decode(
            store.get("identities", &alice).await.unwrap().unwrap(),
        )
        .unwrap();
        let simulated = ctx
            .decisions()
            .unwrap()
            .simulated_principal(&identity, false);
        let keys = risk_context(&store, &simulated, now).await.unwrap();
        assert_eq!(
            Value::Object(keys),
            json!({ "principal.riskLevel": "none", "principal.riskScore": 0 })
        );
    });
}

#[test]
fn end_containment_drops_the_mark_and_keeps_the_score() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        f.insert(
            "identityRisk",
            json!({
                "id": alice, "tenantId": f.tenant_id, "identityId": alice,
                "contributions": [], "score": 40, "level": "medium",
                "contained": { "at": 1, "by": f.owner_id, "reason": "r" },
                "updatedAt": 1,
            }),
        )
        .await;
        f.insert(
            "identityRisk",
            json!({
                "id": bob, "tenantId": f.tenant_id, "identityId": bob,
                "contributions": [], "score": 10, "level": "low", "updatedAt": 1,
            }),
        )
        .await;
        let ids = (alice.clone(), bob.clone());
        f.iam
            .store
            .transaction(|tx| async move {
                end_containment(&tx, &ids.0, 500.0).await?;
                end_containment(&tx, &ids.1, 500.0).await?;
                end_containment(&tx, "nobody", 500.0).await
            })
            .await
            .unwrap();
        let store = f.store();
        let alice_risk = store.get("identityRisk", &alice).await.unwrap().unwrap();
        assert!(!alice_risk.contains_key("contained"));
        assert_eq!(alice_risk["score"], json!(40));
        assert_eq!(alice_risk["updatedAt"], json!(500));
        // Not contained: untouched.
        let bob_risk = store.get("identityRisk", &bob).await.unwrap().unwrap();
        assert_eq!(bob_risk["updatedAt"], json!(1));
    });
}
