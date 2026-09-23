'use client';
import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import type { ImpactPreview } from 'better-iam/server';
import { describeError, iamClient } from '@/lib/client';

export interface ImpactTargets {
  roles: { id: string; name: string; permissions: string[] }[];
  policies: { id: string; name: string; document: unknown }[];
}
type Mode = 'role' | 'policy' | 'deleteRole';

const lines = (value: string) =>
  value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);

/** Previews who gains or loses which actions if a role or policy changes; nothing is saved. */
export function ImpactPreviewForm({
  tenantId,
  base,
  targets,
}: {
  tenantId: string;
  base: string;
  targets: ImpactTargets;
}) {
  const [mode, setMode] = useState<Mode>('role');
  const [roleId, setRoleId] = useState(targets.roles[0]?.id ?? '');
  const [policyId, setPolicyId] = useState(targets.policies[0]?.id ?? '');
  const role = targets.roles.find((item) => item.id === roleId);
  const policy = targets.policies.find((item) => item.id === policyId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [result, setResult] = useState<ImpactPreview | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const change =
        mode === 'role'
          ? { role: { roleId, permissions: lines(String(data.get('permissions') ?? '')) } }
          : mode === 'policy'
            ? {
                policy: {
                  policyId,
                  document: JSON.parse(String(data.get('document') ?? '')) as unknown,
                },
              }
            : { deleteRole: roleId };
      const resources = lines(String(data.get('resources') ?? '')).map((line) => {
        const slash = line.indexOf('/');
        if (slash <= 0) throw new Error(`Write resources as type/id: ${line}`);
        return { type: line.slice(0, slash), id: line.slice(slash + 1) };
      });
      const actions = lines(String(data.get('actions') ?? ''));
      setResult(
        (await iamClient().$request('impact/preview', {
          tenantId,
          change,
          resources,
          ...(actions.length ? { actions } : {}),
          assumeMfa: data.get('assumeMfa') === 'on',
        })) as ImpactPreview,
      );
    } catch (caught) {
      setError(
        caught instanceof SyntaxError || (caught instanceof Error && !('code' in caught))
          ? { code: 'INVALID_INPUT', message: caught.message }
          : describeError(caught),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={onSubmit}>
        <div className="field">
          <label htmlFor="impact-mode">Change</label>
          <select
            id="impact-mode"
            className="select"
            value={mode}
            onChange={(event) => setMode(event.target.value as Mode)}
          >
            <option value="role">Replace a role&apos;s permissions</option>
            <option value="policy">Replace a policy document</option>
            <option value="deleteRole">Delete a role</option>
          </select>
        </div>
        {mode === 'policy' ? (
          <>
            <div className="field">
              <label htmlFor="impact-policy">Policy</label>
              <select
                id="impact-policy"
                className="select"
                value={policyId}
                onChange={(event) => setPolicyId(event.target.value)}
              >
                {targets.policies.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="impact-document">Candidate document (JSON)</label>
              <textarea
                key={policyId}
                id="impact-document"
                className="textarea"
                name="document"
                rows={10}
                defaultValue={policy ? JSON.stringify(policy.document, null, 2) : ''}
                required
              />
            </div>
          </>
        ) : (
          <div className="field">
            <label htmlFor="impact-role">Role</label>
            <select
              id="impact-role"
              className="select"
              value={roleId}
              onChange={(event) => setRoleId(event.target.value)}
            >
              {targets.roles.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </div>
        )}
        {mode === 'role' && (
          <div className="field">
            <label htmlFor="impact-permissions">New permissions</label>
            <textarea
              key={roleId}
              id="impact-permissions"
              className="textarea"
              name="permissions"
              rows={4}
              defaultValue={role?.permissions.join('\n') ?? ''}
              placeholder="documents:read"
              required
            />
            <span className="help">
              One action per line; replaces the role&apos;s inline permissions.
            </span>
          </div>
        )}
        <div className="field">
          <label htmlFor="impact-resources">Resources</label>
          <textarea
            id="impact-resources"
            className="textarea"
            name="resources"
            rows={3}
            placeholder="document/quarterly-report"
            required
          />
          <span className="help">Up to 10, one type/id per line.</span>
        </div>
        <div className="field">
          <label htmlFor="impact-actions">
            Actions <span className="muted">(optional)</span>
          </label>
          <input
            id="impact-actions"
            className="input"
            name="actions"
            placeholder="Every known action"
          />
        </div>
        <div className="field inline">
          <input id="impact-mfa" type="checkbox" name="assumeMfa" />
          <label htmlFor="impact-mfa">Evaluate holders as MFA-verified</label>
        </div>
        {error && (
          <div className="alert danger">
            <strong>{error.code}</strong> — {error.message}
          </div>
        )}
        <div className="form-actions">
          <button className="btn" disabled={busy || (mode === 'policy' ? !policyId : !roleId)}>
            {busy ? 'Working…' : 'Preview impact'}
          </button>
        </div>
      </form>
      {result && (
        <div className="stack">
          <p className="small">
            Affects roles{' '}
            {result.roles.map((item, index) => (
              <span key={item.id}>
                {index > 0 && ', '}
                <Link href={`${base}/roles/${item.id}`}>{item.name}</Link>
              </span>
            ))}
            . Evaluated {result.evaluated} holder(s)
            {result.truncated && ' (capped at 200)'}: {result.gainedTotal} action(s) gained,{' '}
            {result.lostTotal} lost. Nothing was saved.
          </p>
          {result.invariants.broken.map((broken) => (
            <div key={broken.id} className="alert danger">
              <strong>
                {broken.mode === 'enforce' ? 'Would be refused' : 'Breaks a monitored invariant'}
              </strong>{' '}
              — <Link href={`${base}/invariants`}>{broken.name}</Link>:{' '}
              {broken.violations.map((violation) => violation.identity.name).join(', ')}
            </div>
          ))}
          {result.invariants.fixed.map((fixed) => (
            <div key={fixed.id} className="alert success">
              Fixes the invariant <Link href={`${base}/invariants`}>{fixed.name}</Link>.
            </div>
          ))}
          {result.identities.length === 0 ? (
            <div className="alert info">No holder&apos;s access changes on these resources.</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Holder</th>
                  <th>Resource</th>
                  <th>Gains</th>
                  <th>Loses</th>
                </tr>
              </thead>
              <tbody>
                {result.identities.flatMap((entry) =>
                  entry.changes.map((diff) => (
                    <tr key={`${entry.identity.id}:${diff.resource}`}>
                      <td>
                        <Link href={`${base}/members/${entry.identity.id}`}>
                          {entry.identity.name}
                        </Link>
                      </td>
                      <td>
                        <code className="small">{diff.resource}</code>
                      </td>
                      <td className="small">
                        {diff.gained.map((action) => (
                          <span key={action} className="badge success" style={{ marginRight: 4 }}>
                            {action}
                          </span>
                        ))}
                      </td>
                      <td className="small">
                        {diff.lost.map((action) => (
                          <span key={action} className="badge danger" style={{ marginRight: 4 }}>
                            {action}
                          </span>
                        ))}
                      </td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
