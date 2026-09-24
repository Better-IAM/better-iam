import { LaunchButton, RequestAppButton } from '@/components/app-launcher';
import { Alert, Badge, Card, PageHeader, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function MyApps({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const apps = await tryRead(() => iam.api.applications.mine(auth, { tenantId }));
  const available = (apps ?? []).filter((app) => !app.requestPackageId);
  const requestable = (apps ?? []).filter((app) => app.requestPackageId);
  const categories = [...new Set(available.map((app) => app.category ?? 'Apps'))].sort();
  return (
    <>
      <PageHeader
        title="My apps"
        description="The tools your organization gives you, one click away."
      />
      {!apps ? (
        <Alert tone="warning">
          Your apps appear here when you are signed in to your organization.
        </Alert>
      ) : (
        <div className="stack">
          {!available.length && <Alert tone="info">No apps are assigned to you yet.</Alert>}
          {categories.map((category) => (
            <Card key={category} title={category}>
              <div className="tiles">
                {available
                  .filter((app) => (app.category ?? 'Apps') === category)
                  .map((app) => (
                    <div key={app.id} className="card stat">
                      <span className="label row">
                        {app.logoUrl && (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img src={app.logoUrl} alt="" width={20} height={20} />
                        )}
                        {app.name}
                      </span>
                      {app.description && <span className="hint">{app.description}</span>}
                      <span className="row">
                        <LaunchButton tenantId={tenantId} appId={app.id} />
                        {app.lastLaunchedAt ? (
                          <span className="small muted">
                            Last opened <Time value={app.lastLaunchedAt} />
                          </span>
                        ) : (
                          <Badge>new</Badge>
                        )}
                      </span>
                    </div>
                  ))}
              </div>
            </Card>
          ))}
          {requestable.length > 0 && (
            <Card title="More apps" description="Ask for access; an approver decides.">
              <div className="tiles">
                {requestable.map((app) => (
                  <div key={app.id} className="card stat">
                    <span className="label">{app.name}</span>
                    {app.description && <span className="hint">{app.description}</span>}
                    <RequestAppButton tenantId={tenantId} packageId={app.requestPackageId!} />
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
