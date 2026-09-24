/**
 * The console's navigation: every page belongs to one section. A section is a tab in the top bar, a landing page that
 * lists its pages (`{root}/sections/{key}`), and the short sidebar shown while you are in it. Add new pages here.
 * Plain data, shared by the layouts (server) and the navigation components (client).
 */

export interface NavPage {
  href: string;
  label: string;
  /** One line on the section's landing page and in search results. */
  description: string;
  /** Matches only this exact path (a dashboard whose path prefixes every other page). */
  exact?: boolean;
}

export interface NavArea {
  key: string;
  label: string;
  description: string;
  /** Where the tab leads: the section's landing page, or its only page. */
  href: string;
  /** Whether the section has a landing page listing its pages. */
  landing: boolean;
  pages: NavPage[];
}

function area(
  root: string,
  key: string,
  label: string,
  description: string,
  pages: NavPage[],
): NavArea {
  return { key, label, description, href: `${root}/sections/${key}`, landing: true, pages };
}

/** The organization console, rooted at `/cloud/{org}`. */
export function orgAreas(base: string): NavArea[] {
  const page = (path: string, label: string, description: string): NavPage => ({
    href: `${base}/${path}`,
    label,
    description,
  });
  return [
    {
      key: 'home',
      label: 'Home',
      description: 'Your organization at a glance.',
      href: base,
      landing: false,
      pages: [
        {
          href: base,
          label: 'Overview',
          description: 'People, access, and what needs attention, at a glance.',
          exact: true,
        },
        page(
          'workspaces',
          'Workspaces',
          'Projects the organization registers as managed resources.',
        ),
        page('get-started', 'Get started', 'Your own onboarding checklist in this organization.'),
        page('my-apps', 'My apps', 'The tools your organization gives you, one click away.'),
        page('my-privacy', 'Your privacy', 'How your data is used, your choices, and data requests.'),
      ],
    },
    area(base, 'directory', 'Directory', 'Who belongs to the organization, and how they sign in.', [
      page('members', 'Members', 'People who can sign in, and the invitations waiting for them.'),
      page('teams', 'Teams', 'People grouped with maintainers, join requests, and team roles.'),
      page(
        'departments',
        'Departments',
        'The reporting structure: one department per person, with heads.',
      ),
      page('groups', 'Groups', 'Bind roles to a group once; every member inherits them.'),
      page(
        'service-accounts',
        'Service accounts',
        'Non-human identities for integrations, and their API keys.',
      ),
      page(
        'devices',
        'Devices',
        'Registered laptops and phones: owners, assurance, and compliance.',
      ),
      page(
        'device-management',
        'Device management',
        'Compliance requirements, MDM and EDR integrations, and enrollment codes.',
      ),
      page(
        'directory',
        'Directory sync',
        'Let your identity provider manage members and groups over SCIM.',
      ),
      page(
        'domains',
        'Domains',
        'Verified email domains that route people straight to this organization.',
      ),
      page('sign-in-address', 'Sign-in address', 'Your own sign-in subdomain and hostnames.'),
      page(
        'verifiable-credentials',
        'Credentials',
        'Digital badges people keep in their wallets, with selective disclosure and revocation.',
      ),
    ]),
    area(base, 'access', 'Access', 'What people may do, and every way access is granted.', [
      page('roles', 'Roles', 'Named sets of permissions, bound to members and groups.'),
      page('policies', 'Policies', 'Versioned allow and deny statements with conditions.'),
      page(
        'packages',
        'Access packages',
        'Bundles of roles and groups, including birthright access by rule.',
      ),
      page('elevate', 'Elevate', 'Just-in-time roles: activations, approvals, and break glass.'),
      page(
        'access-requests',
        'Access requests',
        'Ask for a role; a reviewer approves under their own authority.',
      ),
      page('agreements', 'Terms of use', 'Agreements members accept, visible to policies.'),
      page(
        'ssh',
        'SSH access',
        'Short-lived SSH certificates for the servers and logins policies allow.',
      ),
      page(
        'workflows',
        'Workflows',
        'Joiner, mover and leaver automation that runs with your rights.',
      ),
      page(
        'applications',
        'Applications',
        'The app catalog on My apps: who sees each app, launches, and unused assignments.',
      ),
    ]),
    area(
      base,
      'governance',
      'Governance',
      'Keep access healthy: reviews, risks, guardrails, and reports.',
      [
        page('governance', 'Health', 'Risks, guardrails, unused access, and reviews in one view.'),
        page(
          'certifications',
          'Certifications',
          'Periodic reviews where reviewers keep or revoke access.',
        ),
        page(
          'reviews',
          'Who can do what',
          'Ask who can perform an action, or what one person can do.',
        ),
        page('findings', 'Security findings', 'Risky or stale access found in the configuration.'),
        page(
          'role-mining',
          'Role mining',
          'Suggested bundles, group grants, duplicate roles, and peer outliers.',
        ),
        page(
          'impact',
          'Change impact',
          'See who gains or loses access before you edit a role or policy.',
        ),
        page(
          'invariants',
          'Invariants',
          'Guardrails over who may, or must never, perform an action.',
        ),
        page('separation-of-duties', 'Separation of duties', 'Roles nobody may hold together.'),
        page(
          'compliance',
          'Compliance',
          'SOC 2, ISO 27001 and NIST controls checked daily, with exceptions and signed evidence.',
        ),
        page(
          'reports',
          'Reports',
          'What ends soon, who holds elevated roles now, and unused keys.',
        ),
      ],
    ),
    area(base, 'security', 'Security', 'Attacks on accounts, and how the organization responds.', [
      page('threats', 'Threats', 'Detections, open incidents, and identities at risk.'),
      page('threats/incidents', 'Incidents', 'Every incident: triage, respond, and resolve.'),
      page(
        'threats/settings',
        'Detection settings',
        'Detection rules, trusted networks, alerts, and automatic playbooks.',
      ),
      page(
        'signals',
        'Shared Signals',
        'Security events from your identity providers: revoked sessions, compromised credentials, risk.',
      ),
    ]),
    area(base, 'ai', 'AI', 'AI agents, what they may do for people, and access to models.', [
      page('agents', 'Agents', 'Agent accounts with sponsors, ceilings, keys, and attested cards.'),
      page('delegations', 'Delegations', 'Let agents act for you, only within what you allow.'),
      page(
        'inference',
        'Models & budgets',
        'Who may call which AI models, and how much they may spend.',
      ),
    ]),
    area(
      base,
      'developers',
      'Developers',
      'Your own resources, integrations, and configuration as code.',
      [
        page(
          'resource-types',
          'Resource types',
          'Managed resource types of your own and their actions.',
        ),
        page('resources', 'Resources', 'Managed resources with owners, parents, and attributes.'),
        page('webhooks', 'Webhooks', 'Signed deliveries of audit events to your endpoints.'),
        page(
          'keys',
          'Keys',
          'Encryption, signing and MAC keys your applications use without ever holding them.',
        ),
        page(
          'certificates',
          'Certificates',
          'A private certificate authority for mutual TLS and SPIFFE workload identity.',
        ),
        page(
          'data-protection',
          'Data protection',
          'Tokenize card numbers and personal data; read them back only for a purpose.',
        ),
        page(
          'vault',
          'Vault',
          'Secrets with versions and rotation, check-outs of shared credentials, dynamic credentials.',
        ),
        page(
          'data-filters',
          'Data filters',
          'Which rows someone may see, as SQL, Prisma, or MongoDB filters for your own queries.',
        ),
        page(
          'provisioning',
          'App provisioning',
          "Keep your SaaS apps' user directories in step over SCIM.",
        ),
        page(
          'configuration',
          'Configuration',
          'Roles, policies, groups, and more as one versioned document.',
        ),
      ],
    ),
    area(
      base,
      'organization',
      'Organization',
      "Settings, billing, and the organization's own records.",
      [
        page('settings', 'Settings', 'Sign-in policy and organization details.'),
        page('billing', 'Billing', 'Spend, budgets, and statements.'),
        page('audit', 'Audit log', 'Every sign-in, change, and denial, in a tamper-evident chain.'),
        page(
          'privacy',
          'Privacy',
          'Purposes and consent, data-subject requests with deadlines, and legal holds.',
        ),
        page('features', 'Features', 'Feature flags for this organization and its projects.'),
        page('onboarding', 'Onboarding', 'Checklists and flows for people who join.'),
        page(
          'setup',
          'Setup checklist',
          'What the platform asks of this organization, ticked off as you go.',
        ),
      ],
    ),
  ];
}

/** The platform administration panel, rooted at `/admin`. */
export function adminAreas(): NavArea[] {
  const root = '/admin';
  const page = (path: string, label: string, description: string): NavPage => ({
    href: `${root}/${path}`,
    label,
    description,
  });
  return [
    {
      key: 'overview',
      label: 'Overview',
      description: 'The platform at a glance.',
      href: root,
      landing: false,
      pages: [
        {
          href: root,
          label: 'Dashboard',
          description: 'The platform at a glance.',
          exact: true,
        },
      ],
    },
    area(
      root,
      'platform',
      'Platform',
      'Organizations, root authority, and what the platform offers.',
      [
        page(
          'organizations',
          'Organizations',
          'Every organization, and owner invitations for new ones.',
        ),
        page(
          'administrators',
          'Root administrators',
          'Who holds root authority over the installation.',
        ),
        page('features', 'Feature flags', 'Platform flags, targets, rollouts, and kill switches.'),
        page('billing', 'Billing', 'Meters, list prices, what organizations owe, and statements.'),
        page('onboarding', 'Onboarding', 'Defaults for member onboarding and new-tenant setup.'),
      ],
    ),
    area(
      root,
      'governance',
      'Governance',
      'Access health across every organization, and the record of it.',
      [
        page(
          'governance',
          'Organization health',
          'Findings, guardrails, reviews, and terms across organizations.',
        ),
        page(
          'catalog',
          'Permission catalog',
          'Resource types and actions declared by the deployment.',
        ),
        page('audit', 'Audit log', 'Denials, root overrides, and administrative changes.'),
      ],
    ),
    area(root, 'security', 'Security', 'Who is signed in, and who is trying to.', [
      page('sessions', 'Live sessions', 'Every unexpired session on the platform.'),
      page(
        'security',
        'Sign-in failures',
        'Failed attempts, credential stuffing, and blocked networks.',
      ),
    ]),
    area(root, 'operations', 'Operations', 'The health of this deployment.', [
      page(
        'operations',
        'Metrics and health',
        'Database, outbox, sessions, and the Prometheus counters.',
      ),
      page('deliveries', 'Deliveries', 'Invitations, links, and codes leaving through the outbox.'),
    ]),
  ];
}

/** Whether `page` is the current page (or an ancestor of it, such as a list above a detail page). */
export function pageMatches(pathname: string, page: Pick<NavPage, 'href' | 'exact'>): boolean {
  return page.exact
    ? pathname === page.href
    : pathname === page.href || pathname.startsWith(`${page.href}/`);
}

/** The section the current path belongs to: its landing page, or the section of the closest matching page. */
export function currentArea(
  areas: NavArea[],
  pathname: string,
): { area: NavArea; page?: NavPage } | undefined {
  const landing = areas.find((item) => item.landing && pathname === item.href);
  if (landing) return { area: landing };
  let best: { area: NavArea; page: NavPage } | undefined;
  for (const item of areas)
    for (const page of item.pages)
      if (pageMatches(pathname, page) && (!best || page.href.length > best.page.href.length))
        best = { area: item, page };
  return best;
}
