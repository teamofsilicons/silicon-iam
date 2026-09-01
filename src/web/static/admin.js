/*
 * Silicon IAM — platform administration console.
 *
 * A thin, dependency-free client over `/api/v1/admin/*`, served same-origin
 * from the API itself. It carries no framework on purpose: this page is opened
 * rarely, by a handful of people, to do a handful of irreversible things, and
 * a 40 KB runtime would buy nothing.
 *
 * Three contract facts shape everything below.
 *
 *   1. Every admin mutation needs a bearer, an `Idempotency-Key`, an
 *      `If-Match` version precondition, AND a verified-channel step-up token
 *      bound to that specific action and resource. There is no way to batch
 *      or cache the step-up; each decision prompts once.
 *   2. Access tokens live 30 minutes and refresh tokens rotate on every use.
 *      Presenting a consumed refresh token revokes the whole family, so the
 *      refresh here is strictly single-flight.
 *   3. Reads are cheap and writes are audited. When in doubt this page
 *      re-reads rather than trusting its own cache, because a stale version
 *      is a `412` and a stale status is a wrong decision.
 *
 * The CSP for this page is `default-src 'none'` widened only to `'self'`, with
 * no `unsafe-inline` and no `unsafe-eval`. Nothing here uses `innerHTML` with
 * interpolated data; every value reaches the DOM through `textContent`.
 */

'use strict';

const API = '/api/v1';

/** In-memory only. A token in storage is a token an XSS can read. */
const session = {
  accessToken: null,
  refreshToken: null,
  expiresAt: 0,
  actor: null,
  refreshInFlight: null,
};

/* ------------------------------------------------------------------ *
 * Transport                                                          *
 * ------------------------------------------------------------------ */

function idempotencyKey() {
  // 16-255 characters; a UUID is 36 and needs no encoding.
  return `admin-${crypto.randomUUID()}`;
}

class ApiError extends Error {
  constructor(status, code, message, requestId) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

async function request(method, path, options = {}) {
  const headers = new Headers({ Accept: 'application/json' });

  if (options.auth !== false) {
    const token = await accessToken();
    if (token === null) throw new ApiError(401, 'unauthenticated', 'Sign in again.', null);
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (options.idempotent === true) headers.set('Idempotency-Key', idempotencyKey());
  if (options.ifMatch !== undefined) headers.set('If-Match', `"${String(options.ifMatch)}"`);
  if (options.stepUpToken !== undefined) headers.set('X-Step-Up-Token', options.stepUpToken);

  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    credentials: 'include',
    cache: 'no-store',
    ...(options.body !== undefined && { body: JSON.stringify(options.body) }),
  });

  const requestId = response.headers.get('X-Request-ID');
  const text = await response.text();
  let payload = null;
  if (text.length > 0) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const error = payload?.error ?? {};
    throw new ApiError(
      response.status,
      typeof error.code === 'string' ? error.code : 'request_failed',
      typeof error.message === 'string' ? error.message : describeStatus(response.status),
      typeof error.request_id === 'string' ? error.request_id : requestId,
    );
  }

  return { data: payload, etag: stripQuotes(response.headers.get('ETag')) };
}

function stripQuotes(value) {
  return value === null ? null : value.replace(/^W\//, '').replace(/^"|"$/g, '');
}

function describeStatus(status) {
  if (status === 403) return 'You do not have permission to do that.';
  if (status === 412) return 'This record changed since you loaded it. Refresh and try again.';
  if (status === 429) return 'Too many requests. Wait and try again.';
  if (status >= 500) return 'Something went wrong on our side.';
  return 'The request could not be completed.';
}

/**
 * Returns a usable access token, refreshing once if needed.
 *
 * Single-flight: refresh tokens rotate on every use, and two concurrent
 * refreshes would consume the same token twice and revoke the family.
 */
async function accessToken() {
  if (session.accessToken !== null && Date.now() < session.expiresAt - 60_000) {
    return session.accessToken;
  }
  if (session.refreshToken === null) return null;

  session.refreshInFlight ??= (async () => {
    try {
      const response = await fetch(`${API}/auth/tokens/refresh`, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey(),
        },
        credentials: 'include',
        cache: 'no-store',
        body: JSON.stringify({ refresh_token: session.refreshToken }),
      });
      if (!response.ok) throw new Error('refresh rejected');
      adoptTokens(await response.json());
      return session.accessToken;
    } catch {
      // Terminal: the family was revoked or the token was already consumed.
      clearSession();
      return null;
    } finally {
      session.refreshInFlight = null;
    }
  })();

  return session.refreshInFlight;
}

function adoptTokens(token) {
  session.accessToken = token.access_token;
  session.refreshToken = token.refresh_token;
  session.expiresAt = Date.now() + token.expires_in * 1000;
  session.actor = token.actor;
}

function clearSession() {
  session.accessToken = null;
  session.refreshToken = null;
  session.expiresAt = 0;
  session.actor = null;
}

/* ------------------------------------------------------------------ *
 * DOM helpers                                                        *
 * ------------------------------------------------------------------ */

const $ = (id) => document.getElementById(id);

function show(view) {
  for (const name of ['loading', 'signin', 'denied', 'console']) {
    const element = $(`view-${name}`);
    if (element !== null) element.hidden = name !== view;
  }
}

function announce(message) {
  const region = $('toast-region');
  if (region !== null) region.textContent = message;
}

/** Builds an element. Text is always assigned, never interpolated into HTML. */
function el(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === undefined || value === null || value === false) continue;
    if (name === 'text') node.textContent = String(value);
    else if (name === 'class') node.className = value;
    else node.setAttribute(name, value === true ? '' : String(value));
  }
  for (const child of children) {
    if (child !== null && child !== undefined) node.append(child);
  }
  return node;
}

function badge(text, tone) {
  return el('span', { class: `badge badge-${tone}`, text });
}

function statusBadge(status) {
  switch (status) {
    case 'verified':
      return badge('verified', 'solid');
    case 'under_review':
      return badge('under review', 'warning');
    case 'suspended':
      return badge('suspended', 'danger');
    case 'rejected':
      return badge('rejected', 'danger');
    case 'deleted':
      return badge('deleted', 'danger');
    default:
      return badge(status, 'bare');
  }
}

function formatDate(value) {
  if (typeof value !== 'string') return '—';
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return '—';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    parsed,
  );
}

/* ------------------------------------------------------------------ *
 * Sign-in                                                            *
 * ------------------------------------------------------------------ */

let loginSessionId = null;

function signInError(message) {
  const element = $('signin-error');
  if (element === null) return;
  element.textContent = message ?? '';
  element.hidden = message === null || message === undefined;
}

$('form-identity')?.addEventListener('submit', (event) => {
  event.preventDefault();
  const value = $('identity').value.trim();
  if (value.length === 0) return;

  signInError(null);
  void (async () => {
    try {
      const identity = value.includes('@') ? { email: value } : { carbon_id: value };
      const { data } = await request('POST', '/login/challenges', {
        auth: false,
        idempotent: true,
        body: identity,
      });
      loginSessionId = data.session_id;
      $('form-identity').hidden = true;
      $('form-code').hidden = false;
      $('code').focus();
      announce('Verification code sent.');
    } catch (cause) {
      signInError(
        cause.status === 404
          ? 'No Silicon IAM account matches that email address or Carbon ID.'
          : cause.message,
      );
    }
  })();
});

$('code-back')?.addEventListener('click', () => {
  loginSessionId = null;
  $('form-code').hidden = true;
  $('form-identity').hidden = false;
  $('code').value = '';
  signInError(null);
});

$('form-code')?.addEventListener('submit', (event) => {
  event.preventDefault();
  const code = $('code').value.trim();
  if (code.length !== 6 || loginSessionId === null) return;

  signInError(null);
  void (async () => {
    try {
      const { data } = await request(
        'POST',
        `/login/challenges/${encodeURIComponent(loginSessionId)}/verify`,
        { auth: false, idempotent: true, body: { code } },
      );
      adoptTokens(data);
      await enterConsole();
    } catch (cause) {
      $('code').value = '';
      signInError(cause.message);
    }
  })();
});

$('sign-out')?.addEventListener('click', () => {
  void (async () => {
    try {
      await request('POST', '/logout', { idempotent: true, body: {} });
    } catch {
      // Sign out locally regardless; the user asked to leave.
    }
    clearSession();
    show('signin');
    $('sign-out').hidden = true;
    $('signed-in').hidden = true;
  })();
});

/**
 * Confirms the signed-in Carbon actually holds a platform-admin grant.
 *
 * There is no "am I an admin" endpoint, and inventing one would widen the
 * public contract for a UI convenience. Probing the queue is the honest test:
 * it either answers or returns `403`, and that is exactly the question.
 */
async function enterConsole() {
  const actor = session.actor;
  if (actor !== null) {
    $('signed-in').textContent = actor.public_id;
    $('signed-in').hidden = false;
    $('sign-out').hidden = false;
  }

  try {
    await loadApplications();
    show('console');
  } catch (cause) {
    if (cause.status === 403) {
      show('denied');
      return;
    }
    show('console');
    announce(cause.message);
  }
}

/* ------------------------------------------------------------------ *
 * Application review                                                 *
 * ------------------------------------------------------------------ */

let statusFilter = 'under_review';

for (const button of document.querySelectorAll('[data-status]')) {
  button.addEventListener('click', () => {
    statusFilter = button.dataset.status;
    for (const other of document.querySelectorAll('[data-status]')) {
      other.setAttribute('aria-pressed', String(other === button));
    }
    void loadApplications().catch((cause) => {
      announce(cause.message);
    });
  });
}

$('refresh')?.addEventListener('click', () => {
  void loadApplications().catch((cause) => {
    announce(cause.message);
  });
});

async function loadApplications() {
  const query = new URLSearchParams({ limit: '100' });
  if (statusFilter !== '') query.set('status', statusFilter);

  const { data } = await request('GET', `/admin/applications?${query.toString()}`);
  renderApplications(data.items ?? []);
  const more = data.page?.has_more === true ? '+' : '';
  $('queue-count').textContent = `${String((data.items ?? []).length)}${more} shown`;
}

function renderApplications(items) {
  const body = $('applications');
  body.replaceChildren();

  if (items.length === 0) {
    body.append(
      el('tr', {}, [
        el('td', { colspan: '8' }, [
          el('p', {
            class: 'small muted',
            text:
              statusFilter === 'under_review'
                ? 'Nothing is waiting for review.'
                : 'No applications match this filter.',
          }),
        ]),
      ]),
    );
    return;
  }

  for (const application of items) {
    const actions = el('td', { class: 'col-actions' }, [
      el('button', { class: 'btn btn-sm', type: 'button' }, [el('span', { text: 'Open' })]),
    ]);
    actions.firstChild.addEventListener('click', () => {
      renderDetail(application);
    });

    body.append(
      el('tr', {}, [
        el('td', {}, [
          el('strong', { text: application.app_name ?? application.app_id }),
          el('br'),
          el('span', { class: 'mono micro', text: application.app_id }),
        ]),
        el('td', { class: 'col-id', text: application.org_id }),
        el('td', {}, [statusBadge(application.status)]),
        el('td', {}, [
          application.notify_users === true
            ? badge('prompts', 'warning')
            : badge('silent', 'bare'),
        ]),
        el('td', {
          class: 'col-id',
          text: `${String((application.approved_scopes ?? []).length)}/${String((application.requested_scopes ?? []).length)}`,
        }),
        el('td', {}, [
          application.has_pending_changes === true
            ? badge('pending', 'warning')
            : el('span', { class: 'soft', text: '—' }),
        ]),
        el('td', { class: 'small', text: formatDate(application.created_at) }),
        actions,
      ]),
    );
  }
}

/** Decisions available for an application, given its current status. */
function decisionsFor(status) {
  switch (status) {
    case 'under_review':
      return [
        { decision: 'approve', label: 'Approve', danger: false },
        { decision: 'reject', label: 'Reject registration', danger: true },
      ];
    case 'verified':
      return [
        { decision: 'suspend', label: 'Suspend', danger: true },
        { decision: 'delete', label: 'Delete permanently', danger: true },
      ];
    case 'suspended':
      return [
        { decision: 'reactivate', label: 'Reactivate', danger: false },
        { decision: 'delete', label: 'Delete permanently', danger: true },
      ];
    case 'rejected':
      return [{ decision: 'delete', label: 'Delete permanently', danger: true }];
    default:
      return [];
  }
}

function renderDetail(application) {
  const panel = $('detail');
  panel.replaceChildren();
  panel.hidden = false;

  const rows = [
    ['Application ID', application.app_id],
    ['Internal ID', application.id],
    ['Organization', application.org_id],
    ['Registered by', application.created_by?.public_id ?? '—'],
    ['Requested scopes', (application.requested_scopes ?? []).join(', ') || '—'],
    ['Approved scopes', (application.approved_scopes ?? []).join(', ') || '—'],
    ['Redirect URIs', (application.redirect_uris ?? []).join('\n') || '—'],
    ['Webhook', application.webhook?.active_url ?? 'not active'],
    ['Pending webhook', application.webhook?.pending_url ?? '—'],
    ['OBO endpoints', String((application.obo_endpoints ?? []).length)],
    ['Version', String(application.version)],
    ['Registered', formatDate(application.created_at)],
  ];

  const list = el('dl', { class: 'kv' });
  for (const [term, value] of rows) {
    list.append(el('dt', { text: term }), el('dd', { class: 'mono', text: value }));
  }

  const buttons = el('div', { class: 'row' });
  for (const option of decisionsFor(application.status)) {
    const button = el(
      'button',
      { class: option.danger ? 'btn btn-danger' : 'btn btn-primary', type: 'button' },
      [el('span', { text: option.label })],
    );
    button.addEventListener('click', () => {
      void decide(application, option);
    });
    buttons.append(button);
  }

  if (application.has_pending_changes === true) {
    for (const option of [
      { decision: 'approve_pending_changes', label: 'Approve pending changes', danger: false },
      { decision: 'reject_pending_changes', label: 'Reject pending changes', danger: true },
    ]) {
      const button = el(
        'button',
        { class: option.danger ? 'btn btn-danger' : 'btn btn-primary', type: 'button' },
        [el('span', { text: option.label })],
      );
      button.addEventListener('click', () => {
        void decide(application, option);
      });
      buttons.append(button);
    }
  }

  // The consent toggle is backend-only and never exposed to an organization.
  const consentButton = el('button', { class: 'btn', type: 'button' }, [
    el('span', {
      text:
        application.notify_users === true
          ? 'Stop prompting for consent'
          : 'Prompt for consent',
    }),
  ]);
  consentButton.addEventListener('click', () => {
    void decide(application, {
      decision: application.status === 'verified' ? 'reactivate' : 'approve',
      label: 'consent policy',
      danger: false,
      notifyUsers: application.notify_users !== true,
    });
  });

  panel.append(
    el('div', { class: 'section-head' }, [
      el('span', { class: 'ordinal', 'aria-hidden': 'true', text: '·' }),
      el('h2', { class: 'label', text: application.app_name ?? application.app_id }),
    ]),
    el('div', { class: 'panel' }, [
      el('div', { class: 'panel-body stack' }, [
        list,
        el('p', {
          class: 'micro',
          text:
            'Consent policy is backend-only. Organization administrators never see or set it, and it is not returned by the organization-facing endpoints.',
        }),
        buttons,
        el('div', { class: 'row' }, [consentButton]),
      ]),
    ]),
  );

  panel.scrollIntoView({ block: 'nearest' });
}

/**
 * Applies a decision, prompting for step-up first.
 *
 * The token is bound to `platform_admin.application_review` on this specific
 * application, so it cannot be reused for another one and is discarded the
 * moment the call returns.
 */
async function decide(application, option) {
  const confirmed = globalThis.confirm(
    `${option.label} for ${application.app_id}?\n\n` +
      (option.decision === 'delete'
        ? 'Deletion is terminal. The application ID is never reused, and every token it issued stops working immediately.'
        : 'This decision is audited and takes effect immediately.'),
  );
  if (!confirmed) return;

  try {
    const stepUpToken = await stepUp(
      'platform_admin.application_review',
      application.id,
      `${option.label} for ${application.app_id}`,
    );
    if (stepUpToken === null) return;

    const body = { decision: option.decision };
    if (option.notifyUsers !== undefined) body.notify_users = option.notifyUsers;
    if (option.decision === 'approve') body.approved_scopes = application.requested_scopes ?? [];

    const { data } = await request(
      'POST',
      `/admin/applications/${encodeURIComponent(application.app_id)}/decisions`,
      { idempotent: true, ifMatch: application.version, stepUpToken, body },
    );

    announce(`${option.label} applied to ${application.app_id}.`);
    await loadApplications();
    if (data !== null) renderDetail(data);
  } catch (cause) {
    announce(cause.message);
    globalThis.alert(
      `${cause.message}${cause.requestId === null ? '' : `\n\nRequest ID: ${cause.requestId}`}`,
    );
  }
}

/* ------------------------------------------------------------------ *
 * SSO entitlement                                                    *
 * ------------------------------------------------------------------ */

$('form-entitlement')?.addEventListener('submit', (event) => {
  event.preventDefault();
  const orgId = $('entitlement-org').value.trim();
  const entitled = $('entitlement-state').value === 'true';
  const version = $('entitlement-version').value.trim();
  if (orgId.length === 0 || version.length === 0) return;

  void (async () => {
    try {
      const stepUpToken = await stepUp(
        'platform_admin.sso_entitlement',
        orgId,
        `${entitled ? 'Entitling' : 'Revoking SSO for'} ${orgId}`,
      );
      if (stepUpToken === null) return;

      await request('PUT', `/admin/organizations/${encodeURIComponent(orgId)}/sso-entitlement`, {
        idempotent: true,
        ifMatch: version,
        stepUpToken,
        body: { entitled },
      });
      announce(`SSO entitlement for ${orgId} set to ${String(entitled)}.`);
      globalThis.alert(`SSO entitlement for ${orgId} is now ${entitled ? 'granted' : 'revoked'}.`);
    } catch (cause) {
      announce(cause.message);
      globalThis.alert(
        `${cause.message}${cause.requestId === null ? '' : `\n\nRequest ID: ${cause.requestId}`}`,
      );
    }
  })();
});

/* ------------------------------------------------------------------ *
 * Step-up                                                            *
 * ------------------------------------------------------------------ */

/**
 * Mints a five-minute, action-bound step-up token.
 *
 * Deliberately not cached. The token is bound to one action on one resource,
 * so caching would buy at most one prompt and would leave a live credential
 * sitting in memory between unrelated decisions.
 */
async function stepUp(action, resourceId, summary) {
  const { data: challenge } = await request('POST', '/step-up/challenges', {
    idempotent: true,
    body: { action, resource_id: resourceId, channel: 'email' },
  });

  const code = globalThis.prompt(
    `${summary}\n\n` +
      'This action needs reauthentication. Enter the six-digit code sent to your verified ' +
      'email address. It is valid for 10 minutes and authorises this one action only.',
  );
  if (code === null || code.trim().length === 0) return null;

  const { data: token } = await request(
    'POST',
    `/step-up/challenges/${encodeURIComponent(challenge.session_id)}/verify`,
    { idempotent: true, body: { code: code.trim() } },
  );
  return token.step_up_token;
}

/* ------------------------------------------------------------------ *
 * Boot                                                               *
 * ------------------------------------------------------------------ */

show('signin');
$('identity')?.focus();
