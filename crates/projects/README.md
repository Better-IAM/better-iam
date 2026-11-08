# better-iam-projects

The reference plugin of [Better IAM](https://github.com/Better-IAM/better-iam) for Rust, the port of
`@better-iam/projects`: tenant-scoped project records with `create`, `list`, `get`, `update`, `archive` and
`restore` endpoints under `POST /api/iam/plugins/projects/...`. Every endpoint runs in the server's transactional
authorization service (root override, tenant scope, ancestry boundaries and policies apply unchanged); endpoints on
one project are authorized on `iam/project/{id}`. Records are shared with the TypeScript plugin.

```rust,ignore
let mut options = BetterIamOptions::new(store, secret, base_url);
options.plugins = Some(vec![better_iam_projects::create_projects_plugin()]);
```
