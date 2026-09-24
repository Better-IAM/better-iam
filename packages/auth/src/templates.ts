import type { DeliveryMessage } from './types.js';

/** A message ready for an email or SMS provider. `html` is only meaningful for email. */
export interface RenderedMessage {
  subject: string;
  text: string;
  html: string;
}

/**
 * Builds the links your application serves for token-carrying templates; a missing builder falls back to the raw
 * token. `signInUrl` is the organization's own sign-in address when the deployment has organization addresses or
 * regions (`DeliveryMessage.signInUrl`), so a link can open on the organization's subdomain or custom hostname.
 */
export interface TemplateLinks {
  invitation?(input: {
    kind: 'owner' | 'member';
    tenantId: string;
    token: string;
    signInUrl?: string;
  }): string;
  passwordReset?(input: { tenantId: string; token: string; signInUrl?: string }): string;
  verifyEmail?(input: { tenantId: string; token: string; signInUrl?: string }): string;
  emailChange?(input: { tenantId: string; token: string; signInUrl?: string }): string;
  magicLink?(input: {
    tenantId: string;
    token: string;
    destination: string;
    signInUrl?: string;
  }): string;
  /** The person's account page (sessions, devices, security activity), used by security notices. */
  account?(input: { tenantId: string; signInUrl?: string }): string;
  /** An access-certification campaign's review page; certification emails fall back to `account`. */
  certification?(input: { tenantId: string; campaignId: string; signInUrl?: string }): string;
  /** Where a person decides on an AI agent's delegation request; falls back to `account`. */
  delegation?(input: { tenantId: string; delegationId: string; signInUrl?: string }): string;
  /** A team's page (join requests, members); team emails fall back to `account`. */
  team?(input: { tenantId: string; teamId: string; signInUrl?: string }): string;
  /** The billing page (spend, budgets, a statement when `statementId` is set); billing emails fall back to `account`. */
  billing?(input: { tenantId: string; statementId?: string; signInUrl?: string }): string;
  /**
   * Privacy links: with `token`, the page that confirms a public data-subject request (it calls
   * `privacy.confirmPublic`); with `handler`, a request's page for whoever handles it; otherwise the person's own
   * privacy page. Privacy emails without a builder fall back to `account` (or show the confirmation code).
   */
  privacy?(input: {
    tenantId: string;
    requestId?: string;
    token?: string;
    handler?: boolean;
    signInUrl?: string;
  }): string;
  /** A security incident's page (threat detection and response); threat alerts fall back to `account`. */
  threats?(input: { tenantId: string; incidentId?: string; signInUrl?: string }): string;
}

export interface TemplateOptions {
  /** Product name used in subjects and greetings (default "Better IAM"). */
  appName?: string;
  links?: TemplateLinks;
}

const escape = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );
/** One line of text: control characters and line separators (which could break a mail header) become spaces. */
const oneLine = (value: string) =>
  value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ').trim();

const browsers: [string, string][] = [
  ['Edg/', 'Edge'],
  ['OPR/', 'Opera'],
  ['SamsungBrowser/', 'Samsung Internet'],
  ['Firefox/', 'Firefox'],
  ['FxiOS/', 'Firefox'],
  ['CriOS/', 'Chrome'],
  ['Chrome/', 'Chrome'],
  ['Safari/', 'Safari'],
];
const systems: [string, string][] = [
  ['Windows', 'Windows'],
  ['iPhone', 'iOS'],
  ['iPad', 'iPadOS'],
  ['Android', 'Android'],
  ['CrOS', 'ChromeOS'],
  ['Macintosh', 'macOS'],
  ['Mac OS X', 'macOS'],
  ['Linux', 'Linux'],
];
/**
 * A short description of a User-Agent for security notices ("Chrome on Windows"). The header is chosen by whoever
 * sent the request, so it never reaches a message verbatim: otherwise anyone could put their own text and links into
 * a genuine sign-in notice by failing a sign-in with a crafted header.
 */
export function describeUserAgent(userAgent: string | undefined): string | undefined {
  if (!userAgent) return undefined;
  const browser = browsers.find(([token]) => userAgent.includes(token))?.[1];
  const system = systems.find(([token]) => userAgent.includes(token))?.[1];
  if (browser && system) return `${browser} on ${system}`;
  return browser ?? (system ? `a browser or app on ${system}` : 'an unrecognized browser or app');
}

function layout(
  appName: string,
  title: string,
  paragraphs: string[],
  action?: { href: string; label: string },
): string {
  const body = paragraphs
    .map((paragraph) => `<p style="margin:0 0 16px">${paragraph}</p>`)
    .join('');
  const button = action
    ? `<p style="margin:0 0 24px"><a href="${escape(action.href)}" style="display:inline-block;padding:10px 18px;background:#1d4ed8;color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600">${escape(action.label)}</a></p><p style="margin:0 0 16px;font-size:13px;color:#555">Or paste this address into your browser:<br><span style="word-break:break-all">${escape(action.href)}</span></p>`
    : '';
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#f5f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111"><div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:10px;padding:32px"><h1 style="font-size:20px;margin:0 0 20px">${escape(title)}</h1>${body}${button}<p style="margin:24px 0 0;font-size:12px;color:#777">${escape(appName)}</p></div></body></html>`;
}

/**
 * Renders the messages Better IAM queues (`verify-email`, `password-reset`, `email-change`, `magic-link`, `code`,
 * `mfa-code`, `new-sign-in`, `sign-in-failures`, `certification-review`, `certification-reminder`, `delegation-request`,
 * `delegation-confirmation`, `team-join-request`, `team-join-decided`, `team-review-requested`, `spend-alert`,
 * `spend-anomaly`, `billing-statement`, `payment-reminder`,
 * `privacy-request-verify`, `privacy-request-received`, `privacy-request-update`, `privacy-request-due`,
 * `workflow-message`,
 * `threat-alert`,
 * `owner-invitation`, `member-invitation`)
 * into a subject, plain text, and HTML, so a
 * delivery callback can hand them to any provider. Returns undefined for templates it does not know (plugins,
 * newer features), which the callback should render itself.
 */
export function renderDeliveryMessage(
  message: Pick<DeliveryMessage, 'template' | 'payload' | 'to'> & {
    tenantId?: string;
    signInUrl?: string;
  },
  options: TemplateOptions = {},
): RenderedMessage | undefined {
  const appName = options.appName ?? 'Better IAM';
  const links = options.links ?? {};
  const { payload } = message;
  // Sign-in emails (verification, reset, magic links) carry their tenant on the message rather than in the payload;
  // invitations carry it in both. Either way, the link builders get it.
  const linkTenant = payload.tenantId ?? message.tenantId ?? '';
  const site = message.signInUrl ? { signInUrl: message.signInUrl } : {};
  // Security notices point at the account page when the application says where it lives.
  const accountAction = message.tenantId
    ? {
        href: links.account?.({ tenantId: message.tenantId, ...site }),
        label: 'Review your account',
      }
    : undefined;
  const tokenLine = (token: string | undefined) => (token ? `Code: ${token}` : '');
  const compose = (
    subject: string,
    title: string,
    lines: string[],
    action?: { href?: string; label: string; fallbackToken?: string },
  ): RenderedMessage => {
    const textLines = [...lines];
    const htmlParagraphs = lines.map(escape);
    let button: { href: string; label: string } | undefined;
    if (action?.href) {
      textLines.push(`${action.label}: ${action.href}`);
      button = { href: action.href, label: action.label };
    } else if (action?.fallbackToken) {
      textLines.push(tokenLine(action.fallbackToken));
      htmlParagraphs.push(`<code>${escape(action.fallbackToken)}</code>`);
    }
    textLines.push('', appName);
    return {
      // Subjects interpolate names and other stored values; a line break there would inject mail headers.
      subject: oneLine(subject),
      text: textLines.join('\n'),
      html: layout(appName, title, htmlParagraphs, button),
    };
  };
  const expiry = (minutes: number) => `This link expires in ${minutes} minutes.`;
  switch (message.template) {
    case 'verify-email':
      return compose(
        `Verify your email for ${appName}`,
        'Verify your email',
        ['Confirm that this address belongs to you.', 'This link is valid for 24 hours.'],
        {
          href: links.verifyEmail?.({
            tenantId: linkTenant,
            ...site,
            token: payload.token ?? '',
          }),
          label: 'Verify email',
          fallbackToken: payload.token,
        },
      );
    case 'password-reset':
      return compose(
        `Reset your ${appName} password`,
        'Reset your password',
        [
          'Someone asked to reset the password for this address. If it was not you, ignore this message.',
          expiry(10),
        ],
        {
          href: links.passwordReset?.({
            tenantId: linkTenant,
            ...site,
            token: payload.token ?? '',
          }),
          label: 'Choose a new password',
          fallbackToken: payload.token,
        },
      );
    case 'email-change':
      return compose(
        `Confirm your new ${appName} email`,
        'Confirm your new email address',
        ['Confirm that you want to sign in with this address from now on.', expiry(10)],
        {
          href: links.emailChange?.({
            tenantId: linkTenant,
            ...site,
            token: payload.token ?? '',
          }),
          label: 'Confirm address',
          fallbackToken: payload.token,
        },
      );
    case 'magic-link':
      return compose(
        `Sign in to ${appName}`,
        'Your sign-in link',
        [
          'Use the link below to sign in. Anyone with it can sign in as you, so do not forward it.',
          expiry(5),
        ],
        {
          href: links.magicLink?.({
            tenantId: linkTenant,
            ...site,
            token: payload.token ?? '',
            destination: message.to,
          }),
          label: 'Sign in',
          fallbackToken: payload.token,
        },
      );
    case 'code':
      return compose(`Your ${appName} sign-in code`, 'Your sign-in code', [
        `Enter this code to sign in: ${payload.token ?? ''}`,
        'It expires in 5 minutes. If you did not request it, ignore this message.',
      ]);
    case 'mfa-code':
      return compose(`Your ${appName} verification code`, 'Your verification code', [
        `Enter this code to finish signing in: ${payload.code ?? ''}`,
        'It expires in a few minutes. If you did not request it, change your password.',
      ]);
    case 'new-sign-in': {
      const where = [
        payload.label ? oneLine(payload.label).slice(0, 80) : undefined,
        describeUserAgent(payload.userAgent),
        payload.ip,
      ]
        .filter(Boolean)
        .join(' · ');
      return compose(
        `New sign-in to ${appName}`,
        'New sign-in to your account',
        [
          `Your account was just used to sign in from a device we had not seen before${where ? `: ${where}` : ''}.`,
          `Method: ${payload.method ?? 'unknown'}. Time: ${payload.time ?? 'unknown'}.`,
          'If this was you, no action is needed. If not, change your password and sign out of every device.',
        ],
        accountAction,
      );
    }
    case 'sign-in-failures': {
      const where = [describeUserAgent(payload.userAgent), payload.ip].filter(Boolean).join(' · ');
      return compose(
        `Failed sign-in attempts on your ${appName} account`,
        'Failed sign-in attempts',
        [
          `${payload.attempts ?? 'Several'} attempts to sign in to your account have failed since your last sign-in${where ? `, the latest from ${where}` : ''}.`,
          `Time of the latest attempt: ${payload.time ?? 'unknown'}.`,
          'Nobody has got in: your password held. If this was not you, change your password anywhere else it is used, and review the security activity on your account page.',
        ],
        accountAction,
      );
    }
    case 'certification-review':
    case 'certification-reminder': {
      const reminder = message.template === 'certification-reminder';
      const campaign = payload.campaignName ?? 'An access review';
      const count = Number(reminder ? payload.pending : payload.items) || 0;
      const due = payload.dueAt ? ` Please decide by ${payload.dueAt}.` : '';
      const tenantId = message.tenantId ?? payload.tenantId;
      const href =
        tenantId && payload.campaignId && links.certification
          ? links.certification({ tenantId, campaignId: payload.campaignId, ...site })
          : tenantId
            ? links.account?.({ tenantId, ...site })
            : undefined;
      return compose(
        reminder ? `Reminder: ${campaign} is waiting for you` : `Review access: ${campaign}`,
        reminder ? 'Access review reminder' : 'You have access to review',
        [
          reminder
            ? `${count} access ${count === 1 ? 'item still needs' : 'items still need'} your decision in ${campaign}.${due}`
            : `You were asked to review ${count} access ${count === 1 ? 'item' : 'items'} in ${campaign}: keep what people still need and revoke the rest.${due}`,
          'Undecided items may be kept or revoked automatically when the review closes.',
        ],
        { href, label: 'Review access' },
      );
    }
    case 'delegation-request': {
      const agent = payload.agentName ?? 'An AI agent';
      const days = Number(payload.days) || 0;
      const tenantId = message.tenantId ?? payload.tenantId;
      const href =
        tenantId && payload.delegationId && links.delegation
          ? links.delegation({ tenantId, delegationId: payload.delegationId, ...site })
          : tenantId
            ? links.account?.({ tenantId, ...site })
            : undefined;
      return compose(
        `${agent} asks to act on your behalf`,
        'An agent asks to act for you',
        [
          `${agent}${payload.model ? ` (${payload.model})` : ''} asks for permission to act on your behalf${days ? ` for ${days} ${days === 1 ? 'day' : 'days'}` : ''}.`,
          `It asks for: ${payload.scopes ?? 'a custom set of permissions'}. It can never do more than you can yourself.`,
          ...(payload.reason ? [`Its reason: “${payload.reason}”`] : []),
          'If you do not recognize this agent, deny the request. You can revoke a delegation at any time.',
        ],
        { href, label: 'Review the request' },
      );
    }
    case 'team-review-requested': {
      const team = payload.teamName ?? 'your team';
      const tenantId = message.tenantId ?? payload.tenantId;
      const href =
        tenantId && payload.teamId && links.team
          ? links.team({ tenantId, teamId: payload.teamId, ...site })
          : tenantId
            ? links.account?.({ tenantId, ...site })
            : undefined;
      const due = payload.dueAt ? new Date(payload.dueAt) : undefined;
      return compose(
        `Review the members of ${team}`,
        `Who still belongs in ${team}?`,
        [
          `An administrator asked the maintainers of ${team} to confirm who still belongs${payload.memberCount ? ` (${payload.memberCount} people)` : ''}: keep the people who still need the team's access, and remove the rest.`,
          ...(due && !Number.isNaN(due.getTime())
            ? [
                `Please decide by ${due.toUTCString()}. ${payload.onUndecided === 'remove' ? 'People nobody decides on then leave the team.' : 'People nobody decides on then stay in the team.'}`,
              ]
            : []),
          ...(payload.note ? [`Note: “${payload.note}”`] : []),
        ],
        { href, label: 'Review the members' },
      );
    }
    case 'team-join-request':
    case 'team-join-decided': {
      const team = payload.teamName ?? 'a team';
      const tenantId = message.tenantId ?? payload.tenantId;
      const href =
        tenantId && payload.teamId && links.team
          ? links.team({ tenantId, teamId: payload.teamId, ...site })
          : tenantId
            ? links.account?.({ tenantId, ...site })
            : undefined;
      if (message.template === 'team-join-request') {
        const who = payload.requesterName ?? 'Someone';
        return compose(
          `${who} asks to join ${team}`,
          `A request to join ${team}`,
          [
            `${who}${payload.requesterEmail ? ` (${payload.requesterEmail})` : ''} asks to join ${team}. Joining gives them the access the team holds.`,
            ...(payload.justification ? [`Their reason: “${payload.justification}”`] : []),
            'As a maintainer of the team you can approve or deny the request.',
          ],
          { href, label: 'Review the request' },
        );
      }
      const approved = payload.decision === 'approved';
      return compose(
        approved ? `You joined ${team}` : `Your request to join ${team} was declined`,
        approved ? `Welcome to ${team}` : 'Join request declined',
        [
          approved
            ? `Your request to join ${team} was approved. You now have the access the team holds.`
            : `Your request to join ${team} was declined.`,
          ...(payload.note ? [`Note from the maintainer: “${payload.note}”`] : []),
        ],
        { href, label: approved ? 'Open the team' : 'Review your account' },
      );
    }
    case 'delegation-confirmation': {
      const agent = payload.agentName ?? 'An AI agent';
      const tenantId = message.tenantId ?? payload.tenantId;
      const href =
        tenantId && payload.delegationId && links.delegation
          ? links.delegation({ tenantId, delegationId: payload.delegationId, ...site })
          : tenantId
            ? links.account?.({ tenantId, ...site })
            : undefined;
      return compose(
        `${agent} asks you to confirm an action`,
        'Confirm an action by your agent',
        [
          `${agent} is acting for you and wants to perform ${payload.action ?? 'an action'} on ${payload.resource ?? 'a resource'}. You asked to confirm actions like this one before it takes them.`,
          ...(payload.reason ? [`Its reason: “${payload.reason}”`] : []),
          `The request expires in ${payload.minutes ?? '30'} minutes. If you do not expect it, reject it and review the agent's access.`,
        ],
        { href, label: 'Review the request' },
      );
    }
    case 'spend-alert':
    case 'spend-anomaly':
    case 'billing-statement':
    case 'payment-reminder': {
      const tenantId = message.tenantId ?? payload.tenantId;
      const statement =
        message.template === 'billing-statement' || message.template === 'payment-reminder';
      const href = tenantId
        ? links.billing
          ? links.billing({
              tenantId,
              ...(statement && payload.statementId ? { statementId: payload.statementId } : {}),
              ...site,
            })
          : links.account?.({ tenantId, ...site })
        : undefined;
      if (message.template === 'spend-anomaly') {
        let items: { what?: string; spent?: string; usual?: string }[] = [];
        try {
          const parsed: unknown = JSON.parse(payload.items ?? '[]');
          if (Array.isArray(parsed)) items = parsed as typeof items;
        } catch {
          // A malformed list still sends the summary.
        }
        const count = Number(payload.count) || items.length;
        const day = payload.day ?? 'yesterday';
        return compose(
          `Unusual spend at ${payload.tenantName ?? 'your organization'} on ${day}`,
          'Unusual spend',
          [
            `${count} ${count === 1 ? 'person, team or meter' : 'people, teams or meters'} spent far more than usual on ${day}:`,
            ...items.map(
              (item) =>
                `${item.what ?? ''}: ${item.spent ?? ''} (usually ${item.usual ?? ''} a day)`,
            ),
            'If this was not expected, find out who or what is behind it before it adds up.',
          ],
          { href, label: 'Review spend' },
        );
      }
      if (message.template === 'payment-reminder') {
        const overdue = payload.overdue === 'true';
        const days = Math.abs(Number(payload.days) || 0);
        const number = payload.number ?? 'your invoice';
        return compose(
          overdue
            ? `Invoice ${number} is ${days} day${days === 1 ? '' : 's'} overdue`
            : `Invoice ${number} is due ${days ? `in ${days} day${days === 1 ? '' : 's'}` : 'today'}`,
          overdue ? 'Payment overdue' : 'Payment reminder',
          [
            `${payload.amountDue ?? 'An amount'} is still due on invoice ${number} for ${payload.tenantName ?? 'your organization'} (${payload.period ?? ''}), due ${payload.dueAt ?? ''}.`.replace(
              ' ()',
              '',
            ),
            overdue
              ? 'Please pay it as soon as you can, or reply if you believe it is wrong.'
              : 'If you have already paid it, you can ignore this reminder.',
          ],
          { href, label: 'View invoice' },
        );
      }
      if (statement) {
        const organization = payload.tenantName ?? 'your organization';
        const subscription = payload.reason === 'subscription';
        return compose(
          `Your ${appName} statement ${payload.number ?? ''} for ${payload.period ?? 'last month'}`.replace(
            /\s+/g,
            ' ',
          ),
          `Statement ${payload.number ?? ''}`.trim(),
          [
            subscription
              ? `The first invoice of the new subscription for ${organization} is ready: ${payload.total ?? 'see the invoice'} due by ${payload.dueAt ?? 'the due date'}.`
              : `The statement for ${organization} for ${payload.period ?? 'last month'} is ready: ${payload.total ?? 'see the statement'} due by ${payload.dueAt ?? 'the due date'}.`,
            `Subtotal ${payload.subtotal ?? ''}, credits applied ${payload.credits ?? '0'}.`,
          ],
          { href, label: 'View statement' },
        );
      }
      const budget = payload.budgetName ?? 'A budget';
      const subject = payload.subjectName ?? 'The budget’s subject';
      const window =
        payload.windowStart && payload.windowEnd && payload.windowStart !== payload.windowEnd
          ? ` (${payload.windowStart} to ${payload.windowEnd})`
          : payload.windowStart
            ? ` (${payload.windowStart})`
            : '';
      const forecast = payload.kind === 'forecast';
      return compose(
        forecast
          ? `${budget} is on track to exceed its budget`
          : `${budget} has reached ${payload.threshold ?? '100'}% of its budget`,
        forecast ? 'Spend forecast alert' : 'Spend alert',
        [
          forecast
            ? `At the current pace ${subject} will spend about ${payload.forecast ?? 'more than planned'} against the ${payload.amount ?? ''} budget “${budget}”${window}.`
            : `${subject} has spent ${payload.spent ?? ''} of the ${payload.amount ?? ''} budget “${budget}”${window}: ${payload.percent ?? payload.threshold ?? ''}%.`,
          ...(!forecast && payload.forecast
            ? [`Projected by the end of the period: ${payload.forecast}.`]
            : []),
          'Review spend by person, team and meter to see what drives it.',
        ],
        { href, label: 'Review spend' },
      );
    }
    case 'privacy-request-verify':
    case 'privacy-request-received':
    case 'privacy-request-update':
    case 'privacy-request-due': {
      const tenantId = message.tenantId ?? payload.tenantId;
      const organization = payload.tenantName ?? 'the organization';
      const number = payload.number ?? 'your request';
      const kinds: Record<string, string> = {
        access: 'a copy of personal data',
        portability: 'personal data in a portable format',
        erasure: 'erasure of personal data',
        rectification: 'correction of personal data',
        restriction: 'restriction of processing',
        objection: 'an objection to processing',
        'opt-out': 'an opt-out of sale or sharing',
      };
      const asked = kinds[payload.type ?? ''] ?? 'a privacy request';
      const due = payload.dueAt ? new Date(Number(payload.dueAt)) : undefined;
      const dueText = due && !Number.isNaN(due.getTime()) ? due.toUTCString() : undefined;
      const link = (extra: { token?: string; handler?: boolean }) =>
        tenantId
          ? links.privacy
            ? links.privacy({
                tenantId,
                ...(payload.requestId ? { requestId: payload.requestId } : {}),
                ...extra,
                ...site,
              })
            : extra.token
              ? undefined
              : links.account?.({ tenantId, ...site })
          : undefined;
      if (message.template === 'privacy-request-verify')
        return compose(
          `Confirm your privacy request to ${organization}`,
          'Confirm your request',
          [
            `We received a request for ${asked} from this address (reference ${number}). Confirm it so ${organization} can start handling it.`,
            'If you did not make this request, ignore this email: nothing happens until it is confirmed, and it lapses after seven days.',
            ...(payload.requestId && !links.privacy ? [`Request ID: ${payload.requestId}`] : []),
          ],
          {
            href: link({ token: payload.token ?? '' }),
            label: 'Confirm request',
            fallbackToken: payload.token,
          },
        );
      if (message.template === 'privacy-request-received')
        return compose(
          `New privacy request ${number}: ${asked}`,
          'A privacy request needs handling',
          [
            `${organization} received a request for ${asked} (${number}${payload.regulation ? `, ${payload.regulation.toUpperCase()}` : ''}${payload.channel ? `, via ${payload.channel}` : ''}).`,
            ...(dueText ? [`It must be answered by ${dueText}.`] : []),
          ],
          { href: link({ handler: true }), label: 'Open the request' },
        );
      if (message.template === 'privacy-request-due') {
        const overdue = payload.overdue === 'true';
        return compose(
          overdue ? `Privacy request ${number} is overdue` : `Privacy request ${number} is due soon`,
          overdue ? 'Privacy request overdue' : 'Privacy request due soon',
          [
            overdue
              ? `The request for ${asked} (${number}) at ${organization} passed its deadline${dueText ? ` on ${dueText}` : ''}. Answer it now, or extend it if the regulation allows and you have not yet.`
              : `The request for ${asked} (${number}) at ${organization} must be answered by ${dueText ?? 'its deadline'}.`,
          ],
          { href: link({ handler: true }), label: 'Open the request' },
        );
      }
      const event = payload.event ?? 'completed';
      const reasons: Record<string, string> = {
        unverified: 'we could not confirm who made it',
        unfounded: 'it is manifestly unfounded',
        excessive: 'it is excessive or repetitive',
        exempt: 'a legal exemption applies (for example a legal obligation to keep the data)',
        duplicate: 'it repeats a request already being handled',
        'no-data': 'it holds no personal data about you',
        other: 'of the reason given by the organization',
      };
      const lines =
        event === 'extended'
          ? [
              `${organization} needs more time to answer your request for ${asked} (${number}).`,
              ...(dueText ? [`You will receive an answer by ${dueText}.`] : []),
            ]
          : event === 'rejected'
            ? [
                `${organization} declined your request for ${asked} (${number}) because ${reasons[payload.reason ?? 'other'] ?? reasons.other}.`,
                'You may contact the organization’s privacy contact, or lodge a complaint with a data protection authority.',
              ]
            : [
                `${organization} completed your request for ${asked} (${number}).`,
                ...(payload.exportReady === 'true'
                  ? [
                      'Your data is ready to download for a limited time from your privacy page after signing in.',
                    ]
                  : []),
                ...(payload.type === 'erasure'
                  ? ['Your personal data has been erased; this is the last message about it.']
                  : []),
              ];
      return compose(
        event === 'extended'
          ? `More time needed for your privacy request ${number}`
          : event === 'rejected'
            ? `Your privacy request ${number} was declined`
            : `Your privacy request ${number} is complete`,
        event === 'extended'
          ? 'Request extended'
          : event === 'rejected'
            ? 'Request declined'
            : 'Request complete',
        lines,
        payload.type === 'erasure' && event === 'completed'
          ? undefined
          : { href: link({}), label: 'View your privacy settings' },
      );
    }
    case 'threat-alert': {
      const tenantId = message.tenantId ?? payload.tenantId;
      const href = tenantId
        ? links.threats
          ? links.threats({
              tenantId,
              ...(payload.incidentId ? { incidentId: payload.incidentId } : {}),
              ...site,
            })
          : links.account?.({ tenantId, ...site })
        : undefined;
      const organization = payload.tenantName ?? 'your organization';
      const title = payload.title ?? 'Suspicious activity';
      const severity = payload.severity ?? 'unknown';
      const count = Number(payload.detections) || 1;
      return compose(
        `${severity.charAt(0).toUpperCase()}${severity.slice(1)} security incident at ${organization}: ${title}`,
        'Security incident',
        [
          `${title}${payload.subject ? ` involving ${payload.subject}` : ''} at ${organization}.`,
          ...(payload.summary ? [payload.summary] : []),
          `Severity: ${severity}. ${count} ${count === 1 ? 'detection' : 'detections'} so far.`,
          'If this activity was not expected, open the incident and respond: end the sessions, contain the account, or block the network.',
        ],
        { href, label: 'Review the incident' },
      );
    }
    case 'workflow-message': {
      // Written by an administrator in a lifecycle workflow: plain text, one paragraph per line.
      const subject = (payload.subject ?? `A message from ${payload.tenantName ?? appName}`).slice(0, 300);
      const lines = (payload.body ?? '').split(/\r?\n/).slice(0, 200);
      return compose(subject, subject, lines, message.tenantId ? accountAction : undefined);
    }
    case 'owner-invitation':
    case 'member-invitation': {
      const kind = message.template === 'owner-invitation' ? 'owner' : 'member';
      const tenantName = payload.tenantName ?? 'an organization';
      const lead =
        kind === 'owner'
          ? `You have been invited to set up ${tenantName} as its owner.`
          : `${payload.inviterName ? `${payload.inviterName} invited` : 'You have been invited'} you to join ${tenantName}.`;
      return compose(
        `${kind === 'owner' ? 'Set up' : 'Join'} ${tenantName} on ${appName}`,
        kind === 'owner' ? `Set up ${tenantName}` : `Join ${tenantName}`,
        [lead, 'The invitation is personal and expires; accept it from the same email address.'],
        {
          href: links.invitation?.({
            kind,
            tenantId: linkTenant,
            ...site,
            token: payload.token ?? '',
          }),
          label: 'Accept invitation',
          fallbackToken: payload.token,
        },
      );
    }
    default:
      return undefined;
  }
}
