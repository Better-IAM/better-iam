//! Credential resolution of stored rows: the unknown-kind case of tests/credential-resolution.test.ts ("still
//! resolves legacy unprefixed API-key and role rows, and fails closed on unknown kinds").

mod organization_fixture;

use better_iam_core::Filter;
use better_iam_server::utils::hash;
use organization_fixture::{bearer, organization, run};
use serde_json::json;

#[test]
fn fails_closed_on_an_unknown_stored_session_kind() {
    run(|| async {
        let f = organization(|_| {}).await;
        let token = "LFurM3y-_TRgl--8L99ahtTy8hoiuUeHokhkgzRkS_A";
        let id = uuid::Uuid::new_v4().to_string();
        let now = f.now();
        f.insert(
            "sessions",
            json!({
                "id": id,
                "tenantId": f.tenant_id,
                "identityId": f.owner_id,
                "kind": "gizmo",
                "tokenHash": hash(token),
                "uniqueKey": hash(token),
                "createdAt": now,
                "lastSeenAt": now,
                "authenticatedAt": now,
                "expiresAt": now + 86_400_000.0,
                "mfa": false,
            }),
        )
        .await;

        // Refused as an unknown kind (after the identity and tenant checks), not as a corrupt record.
        let error = f.iam.authenticate(&bearer(token)).await.unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str(), error.status),
            ("UNAUTHENTICATED", "Invalid credential kind", 401)
        );

        // The stored row keeps its kind.
        let rows = f.find("sessions", Filter::new().eq("id", id.clone())).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["kind"], json!("gizmo"));
    });
}
