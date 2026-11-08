//! Verifiable credentials (`commands/vc.ts`): the scheduler job (no credential).

use super::{only_tenant, tenant_input, to_json};
use crate::framework::{CommandSpec, CommandTarget, define_command};

pub fn vc_commands() -> Vec<CommandSpec> {
    vec![
        define_command("vc-sweep", "Revoke verifiable credentials of people who left", |context| async move {
            let input = tenant_input(&context.flags);
            let result = context.iam()?.verifiable_credentials.sweep(Some(&input)).await?;
            Ok(Some(to_json(&result)?))
        })
        .group("Operations")
        .description(
            "vc-sweep revokes every valid verifiable credential (or one --tenant's) whose holder is no longer an active member, in the Token Status List verifiers read, and audits each as vc:credential:revoke. A deployment operation; run it hourly.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", only_tenant()),
    ]
}
