# better-iam-middleware

Framework middleware for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of the
`@better-iam/middleware` npm package.

- `IamTower` is a tower layer (for axum, hyper, and any tower-based server): it serves the IAM API under its `serve`
  prefixes through the server's node transport (so protocol mounts such as the OAuth provider work too) and gives every
  other request an `IamRequest` in its extensions.
- `IamRequest` holds the per-request helpers: `get_session`, `require_session` (with step-up), `require`, `can`
  (checks made together share one `authorizeMany` call), `authorize`, `list_accessible`, `plan`, `assertion`, an
  in-process client whose transport is the IAM handler, and `sign_out`. Sessions and decisions are memoized for the
  request, and cookies the in-process client receives count for its later calls and go on its response.
- Route guards (`require_session`, `authorize`) check the session, step-up, the authorization, and the CSRF boundary
  (cookie-authenticated unsafe requests must come from a trusted origin). Refusals answer with the IAM JSON error
  envelope, or a 303 to the login / step-up page for page navigations.
- The `axum` feature makes `IamRequest` an extractor, `MiddlewareError` a response, and reads route parameters for
  guard callbacks (`path_param`). The `actix-web` feature provides the same integration as actix-web middleware,
  guards, an extractor, and `ResponseError`.

```rust,ignore
use better_iam_middleware::layer::{IamLayerOptions, IamTower};
use better_iam_middleware::{AuthorizeRule, IamRequest, MiddlewareError};

let iam_tower = IamTower::new(iam.clone(), IamLayerOptions {
    login_path: Some("/login".into()),
    step_up_path: Some("/verify".into()),
    ..Default::default()
});
let app = axum::Router::new()
    .route("/me", get(|iam: IamRequest<BetterIam>| async move {
        iam.require_session(None).await.map(axum::Json)
    }))
    .route("/admin", get(admin).route_layer(iam_tower.authorize(AuthorizeRule::new("iam:identities:update"), None)))
    .layer(iam_tower.layer());
```

Any `BetterIam` (or a value that borrows one: `Arc<BetterIam>`, your application state) is an `IamLike`; other
implementations of the trait can stand in for tests.
