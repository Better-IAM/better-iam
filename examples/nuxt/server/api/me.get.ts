/** A server route protected with the auto-imported utilities. */
export default defineEventHandler(async (event) => {
  const { identity, session } = await requireIamSession(event);
  const access = await iamCan(event, {
    tenantId: session.tenantId,
    checks: [{ action: 'iam:identities:read' }],
  });
  return {
    id: identity.id,
    email: identity.email,
    canReadMembers: access[`iam:identities:read@iam/${session.tenantId}`],
  };
});
