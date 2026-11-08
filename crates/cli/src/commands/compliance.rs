//! Compliance center (`commands/compliance.ts`): the scheduler job (no credential).

use super::{only_tenant, tenant_input};
use crate::framework::{CommandSpec, CommandTarget, define_command};

pub fn compliance_commands() -> Vec<CommandSpec> {
    vec![
        define_command("compliance-evaluate", "Evaluate compliance controls", |context| async move {
            let input = tenant_input(&context.flags);
            Ok(Some(context.iam()?.compliance.evaluate_all(Some(&input)).await?))
        })
        .group("Operations")
        .description(
            "compliance-evaluate runs the enabled compliance controls of every active tenant (or one --tenant's), records the results and a run, and audits it as compliance:evaluate. Tenants whose evaluation failed are listed under failed; their controls show as stale after three days. A deployment operation; run it daily.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", only_tenant()),
    ]
}
