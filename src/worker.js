const SESSION_COOKIE = "ct_session";
const GOOGLE_STATE_COOKIE = "ct_google_state";
const SESSION_DAYS = 30;
const MAX_RECIPIENTS = 10;
const FREQUENCIES = new Set(["daily", "weekly", "every_other_week"]);
const POLAR_PLANS = {
  "558191f1-142c-4f6d-9fba-e37762e9172e": { key: "starter", name: "Care Text Starter", maxRecipients: 3 },
  "7b70bf10-db14-42f1-95f2-741ea82a42fc": { key: "family", name: "Care Text Family", maxRecipients: 10 }
};
const POLAR_BENEFITS = {
  "b7a6a2ca-56e0-4b3f-b21d-40c55c97a5c4": { key: "starter", name: "Care Text Starter", maxRecipients: 3 },
  "b58fd02b-cfb2-4d7c-b141-308464bd2058": { key: "family", name: "Care Text Family", maxRecipients: 10 }
};
const POLAR_CHECKOUT_LINKS = {
  starter: "https://buy.polar.sh/polar_cl_bbaW1XFCdx2IRVgcDZfq5mdRTNGVD3eW9svYF2IRdAB",
  family: "https://buy.polar.sh/polar_cl_ZKINA0MWrAhTJdtbd2x27c203zYKoRNkWlmGW2IyhNO"
};

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, env, ctx, url);
      }

      if (isStaticAssetPath(url.pathname)) {
        return env.ASSETS.fetch(assetRequest(request, url));
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(JSON.stringify({ level: "error", message: error.message, stack: error.stack }));
      return json({ error: "Unexpected error" }, 500);
    }
  }
};

function isStaticAssetPath(pathname) {
  return /\.[a-z0-9]{2,8}$/i.test(pathname);
}

function assetRequest(request, url) {
  const assetUrl = new URL(url);
  assetUrl.search = "";
  return new Request(assetUrl.toString(), request);
}

async function handleApi(request, env, ctx, url) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }

  const route = `${request.method} ${url.pathname}`;

  if (route === "POST /api/auth/register") return register(request, env);
  if (route === "POST /api/auth/login") return login(request, env);
  if (route === "POST /api/auth/logout") return logout(request, env);
  if (route === "GET /api/auth/me") return me(request, env);
  if (route === "GET /api/auth/google/start") return googleStart(request, env, url);
  if (route === "GET /api/auth/google/callback") return googleCallback(request, env, url);
  if (route === "GET /api/taxonomy") return listTaxonomy(env);
  if (route === "POST /api/webhooks/polar") return polarWebhook(request, env);

  const session = await requireSession(request, env);
  if (session instanceof Response) return session;

  if (route === "GET /api/profile") return getProfile(env, session.userId);
  if (route === "GET /api/billing/license") return getBillingLicense(env, session.userId);
  if (route === "POST /api/billing/checkout") return createBillingCheckout(request, env, session.userId);
  if (route === "PUT /api/profile") return updateProfile(request, env, session.userId);
  if (route === "POST /api/subscriber-invites/send") return sendSubscriberInvite(request, env, session.userId);
  if (route === "GET /api/recipients") return listRecipients(env, session.userId);
  if (route === "POST /api/recipients") return createRecipient(request, env, session.userId);

  const recipientMatch = url.pathname.match(/^\/api\/recipients\/([^/]+)$/);
  if (recipientMatch && request.method === "PUT") {
    return updateRecipient(request, env, session.userId, recipientMatch[1]);
  }
  if (recipientMatch && request.method === "DELETE") {
    return deleteRecipient(env, session.userId, recipientMatch[1]);
  }

  return json({ error: "Not found" }, 404);
}

async function register(request, env) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
  const displayName = cleanString(body.displayName, 80);

  if (!email || !username || password.length < 10) {
    return json({ error: "Email, username, and a password of at least 10 characters are required." }, 400);
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1"
  ).bind(email, username).first();
  if (existing) return json({ error: "A user with that email or username already exists." }, 409);

  const { hash, salt } = await hashPassword(password);
  const userId = crypto.randomUUID();

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, username, password_hash, password_salt, display_name) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(userId, email, username, hash, salt, displayName || username),
    env.DB.prepare("INSERT INTO user_profiles (user_id, first_name, last_name) VALUES (?, ?, ?)")
      .bind(userId, "", "")
  ]);

  return createSessionResponse(request, env, userId, { user: await loadUser(env, userId) }, 201);
}

async function login(request, env) {
  const body = await readJson(request);
  const identifier = String(body.identifier || body.username || body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!identifier || !password) return json({ error: "Username/email and password are required." }, 400);

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE lower(email) = ? OR lower(username) = ? LIMIT 1"
  ).bind(identifier, identifier).first();

  if (!user || !user.password_hash || !user.password_salt) {
    return json({ error: "Invalid credentials." }, 401);
  }

  const ok = await verifyPassword(password, user.password_salt, user.password_hash);
  if (!ok) return json({ error: "Invalid credentials." }, 401);

  return createSessionResponse(request, env, user.id, { user: publicUser(user) });
}

async function logout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) {
    const tokenHash = await sha256Hex(token);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
  return json({ ok: true }, 200, { "Set-Cookie": expireCookie(SESSION_COOKIE) });
}

async function me(request, env) {
  const session = await requireSession(request, env);
  if (session instanceof Response) return json({ user: null }, 200);
  await linkLicensesForUser(env, session.userId);
  return json({ user: await loadUser(env, session.userId) });
}

function googleStart(request, env, url) {
  if (!env.GOOGLE_CLIENT_ID) {
    return json({ error: "Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET." }, 501);
  }

  const state = randomToken(32);
  const redirectUri = googleRedirectUri(url, env);
  const google = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  google.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  google.searchParams.set("redirect_uri", redirectUri);
  google.searchParams.set("response_type", "code");
  google.searchParams.set("scope", "openid email profile");
  google.searchParams.set("state", state);
  google.searchParams.set("prompt", "select_account");

  return redirect(google.toString(), {
    "Set-Cookie": cookie(GOOGLE_STATE_COOKIE, state, { maxAge: 600, httpOnly: true, sameSite: "Lax", secure: isHttps(url) })
  });
}

async function googleCallback(request, env, url) {
  const expectedState = getCookie(request, GOOGLE_STATE_COOKIE);
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");

  if (!expectedState || !state || expectedState !== state || !code) {
    return json({ error: "Invalid Google sign-in state." }, 400, { "Set-Cookie": expireCookie(GOOGLE_STATE_COOKIE) });
  }

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: googleRedirectUri(url, env)
    })
  });

  if (!tokenRes.ok) {
    return json({ error: "Google token exchange failed." }, 502, { "Set-Cookie": expireCookie(GOOGLE_STATE_COOKIE) });
  }

  const token = await tokenRes.json();
  const userInfoRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${token.access_token}` }
  });
  if (!userInfoRes.ok) {
    return json({ error: "Google profile lookup failed." }, 502, { "Set-Cookie": expireCookie(GOOGLE_STATE_COOKIE) });
  }

  const profile = await userInfoRes.json();
  if (!profile.sub || !profile.email) return json({ error: "Google profile was incomplete." }, 502);

  const userId = await upsertGoogleUser(env, profile);
  const response = await createSessionResponse(request, env, userId, null, 302, { Location: "/app.html" });
  response.headers.append("Set-Cookie", expireCookie(GOOGLE_STATE_COOKIE));
  return response;
}

async function upsertGoogleUser(env, profile) {
  const identity = await env.DB.prepare(
    "SELECT user_id FROM auth_identities WHERE provider = 'google' AND provider_user_id = ? LIMIT 1"
  ).bind(profile.sub).first();
  if (identity) return identity.user_id;

  const email = normalizeEmail(profile.email);
  const existingUser = await env.DB.prepare("SELECT id FROM users WHERE email = ? LIMIT 1").bind(email).first();
  const userId = existingUser?.id || crypto.randomUUID();
  const displayName = cleanString(profile.name || email, 120);

  if (!existingUser) {
    await env.DB.prepare(
      "INSERT INTO users (id, email, username, display_name, avatar_url) VALUES (?, ?, ?, ?, ?)"
    ).bind(userId, email, null, displayName, profile.picture || null).run();
    await env.DB.prepare("INSERT INTO user_profiles (user_id, first_name, last_name) VALUES (?, ?, ?)")
      .bind(userId, profile.given_name || "", profile.family_name || "").run();
  }

  await env.DB.prepare(
    "INSERT INTO auth_identities (id, user_id, provider, provider_user_id, email) VALUES (?, ?, 'google', ?, ?)"
  ).bind(crypto.randomUUID(), userId, profile.sub, email).run();

  return userId;
}

async function listTaxonomy(env) {
  const result = await env.DB.prepare(
    "SELECT key, name, message_mode AS messageMode, use_case AS useCase FROM taxonomy_categories ORDER BY rowid"
  ).all();
  return json({ categories: result.results || [] });
}

async function getProfile(env, userId) {
  const profile = await env.DB.prepare(
    "SELECT first_name AS firstName, last_name AS lastName, timezone, phone_number AS phoneNumber FROM user_profiles WHERE user_id = ?"
  ).bind(userId).first();
  return json({ profile });
}

async function getBillingLicense(env, userId) {
  await linkLicensesForUser(env, userId);
  const licenses = await env.DB.prepare(
    `SELECT plan, status, product_name AS productName, license_key_display AS licenseKeyDisplay,
      granted_at AS grantedAt, revoked_at AS revokedAt, subscription_id AS subscriptionId
     FROM user_licenses
     WHERE user_id = ?
     ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, updated_at DESC`
  ).bind(userId).all();

  const rows = licenses.results || [];
  const active = rows.find(row => row.status === "active");
  const plan = active ? planDetails(active.plan) : null;
  return json({
    active: Boolean(active),
    plan,
    licenses: rows.map(row => ({ ...row, plan: planDetails(row.plan) }))
  });
}

async function createBillingCheckout(request, env, userId) {
  const body = await readJson(request);
  const requestedPlan = cleanString(body.plan, 24).toLowerCase();
  const plan = requestedPlan === "family" ? "family" : "starter";
  return json({ url: POLAR_CHECKOUT_LINKS[plan], plan: planDetails(plan) });
}

async function updateProfile(request, env, userId) {
  const body = await readJson(request);
  const firstName = cleanString(body.firstName, 80);
  const lastName = cleanString(body.lastName, 80);
  const timezone = cleanString(body.timezone, 80) || "America/Denver";
  const phoneNumber = cleanString(body.phoneNumber, 32);

  await env.DB.prepare(
    "UPDATE user_profiles SET first_name = ?, last_name = ?, timezone = ?, phone_number = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?"
  ).bind(firstName, lastName, timezone, phoneNumber, userId).run();

  return getProfile(env, userId);
}

async function sendSubscriberInvite(request, env, userId) {
  const body = await readJson(request);
  const subscriberPhone = normalizeE164(body.subscriberPhone);
  const connectionName = cleanString(body.connectionName, 100) || "your connection";
  const senderName = cleanString(body.senderName, 100) || "someone who cares about you";
  const messageType = cleanString(body.messageType, 180) || "encouragement";
  const careTextNumber = cleanString(env.CARE_TEXT_NUMBER || body.careTextNumber, 40) || "[Care Text Number]";

  if (!subscriberPhone) {
    return json({ error: "Subscriber phone number must use E.164 format, such as +15551234567." }, 400);
  }

  const message = buildSubscriberInviteMessage({ connectionName, senderName, messageType, careTextNumber });
  const result = await sendSms(env, subscriberPhone, message);

  return json({
    ...result,
    to: subscriberPhone,
    message
  }, result.ok ? 200 : result.status || 501);
}

function buildSubscriberInviteMessage({ connectionName, senderName, messageType, careTextNumber }) {
  return `Care Text invite for ${connectionName}:

Hi ${connectionName}, it's ${senderName}. I want to send you periodic ${messageType} messages through Care Text to tell you I care and to stay connected.

To accept, text JOIN to ${careTextNumber}.

Message frequency may vary. Message and data rates may apply. Reply HELP for help or STOP to opt out.

Forward this to ${connectionName} from your own phone.`;
}

async function sendSms(env, to, message) {
  if (env.SMS_DRY_RUN === "true") return { ok: true, dryRun: true, provider: "dry-run" };

  const region = cleanString(env.AWS_SMS_REGION, 40) || cleanString(env.AWS_REGION, 40) || "us-east-2";
  const accessKeyId = cleanString(env.AWS_ACCESS_KEY_ID, 160);
  const secretAccessKey = cleanString(env.AWS_SECRET_ACCESS_KEY, 240);
  const sessionToken = cleanString(env.AWS_SESSION_TOKEN, 2000);
  const originationIdentity = cleanString(env.AWS_SMS_ORIGINATION_IDENTITY, 160);
  const configurationSetName = cleanString(env.AWS_SMS_CONFIGURATION_SET_NAME, 160);

  if (!accessKeyId || !secretAccessKey || !originationIdentity) {
    return {
      ok: false,
      dryRun: true,
      status: 501,
      provider: "aws-end-user-messaging",
      error: "AWS SMS sending is not configured. Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SMS_ORIGINATION_IDENTITY, and optionally AWS_SMS_REGION/AWS_SMS_CONFIGURATION_SET_NAME."
    };
  }

  const payload = {
    DestinationPhoneNumber: to,
    MessageBody: message,
    MessageType: "TRANSACTIONAL",
    OriginationIdentity: originationIdentity
  };
  if (configurationSetName) payload.ConfigurationSetName = configurationSetName;

  const endpoint = `https://sms-voice.${region}.amazonaws.com/v2/text/outbound-messages`;
  const signed = await awsSignedRequest({
    method: "POST",
    url: endpoint,
    region,
    service: "sms-voice",
    accessKeyId,
    secretAccessKey,
    sessionToken,
    body: JSON.stringify(payload)
  });

  const response = await fetch(endpoint, signed);
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      provider: "aws-end-user-messaging",
      error: data.message || data.Message || data.__type || "AWS SMS send failed.",
      details: data
    };
  }

  return {
    ok: true,
    provider: "aws-end-user-messaging",
    messageId: data.MessageId || data.messageId || null,
    details: data
  };
}

async function listRecipients(env, userId) {
  const recipients = await env.DB.prepare(
    "SELECT id, display_name AS displayName, relationship, phone_number AS phoneNumber, timezone, active FROM recipients WHERE user_id = ? ORDER BY created_at"
  ).bind(userId).all();

  const settings = await env.DB.prepare(
    `SELECT rts.recipient_id AS recipientId, rts.taxonomy_key AS taxonomyKey, tc.name AS taxonomyName, rts.frequency, rts.active
     FROM recipient_taxonomy_settings rts
     JOIN recipients r ON r.id = rts.recipient_id
     JOIN taxonomy_categories tc ON tc.key = rts.taxonomy_key
     WHERE r.user_id = ?
     ORDER BY r.created_at, tc.rowid`
  ).bind(userId).all();

  const byRecipient = new Map();
  for (const setting of settings.results || []) {
    const list = byRecipient.get(setting.recipientId) || [];
    list.push(setting);
    byRecipient.set(setting.recipientId, list);
  }

  return json({
    recipients: (recipients.results || []).map(recipient => ({
      ...recipient,
      active: Boolean(recipient.active),
      taxonomySettings: byRecipient.get(recipient.id) || []
    }))
  });
}

async function createRecipient(request, env, userId) {
  const body = await readJson(request);
  const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM recipients WHERE user_id = ?").bind(userId).first();
  if ((count?.count || 0) >= MAX_RECIPIENTS) {
    return json({ error: `Each user can add up to ${MAX_RECIPIENTS} phone numbers.` }, 400);
  }

  const recipient = normalizeRecipient(body);
  if (!recipient.displayName || !recipient.phoneNumber) {
    return json({ error: "Recipient name and phone number are required." }, 400);
  }

  const recipientId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO recipients (id, user_id, display_name, relationship, phone_number, timezone) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(recipientId, userId, recipient.displayName, recipient.relationship, recipient.phoneNumber, recipient.timezone).run();

  await replaceTaxonomySettings(env, recipientId, body.taxonomySettings || []);
  return json({ id: recipientId }, 201);
}

async function updateRecipient(request, env, userId, recipientId) {
  const body = await readJson(request);
  const existing = await env.DB.prepare(
    "SELECT id FROM recipients WHERE id = ? AND user_id = ? LIMIT 1"
  ).bind(recipientId, userId).first();
  if (!existing) return json({ error: "Recipient not found." }, 404);

  const recipient = normalizeRecipient(body);
  if (!recipient.displayName || !recipient.phoneNumber) {
    return json({ error: "Recipient name and phone number are required." }, 400);
  }

  await env.DB.prepare(
    "UPDATE recipients SET display_name = ?, relationship = ?, phone_number = ?, timezone = ?, active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
  ).bind(recipient.displayName, recipient.relationship, recipient.phoneNumber, recipient.timezone, body.active === false ? 0 : 1, recipientId, userId).run();

  await replaceTaxonomySettings(env, recipientId, body.taxonomySettings || []);
  return json({ ok: true });
}

async function deleteRecipient(env, userId, recipientId) {
  await env.DB.prepare("DELETE FROM recipients WHERE id = ? AND user_id = ?").bind(recipientId, userId).run();
  return json({ ok: true });
}

async function replaceTaxonomySettings(env, recipientId, settings) {
  await env.DB.prepare("DELETE FROM recipient_taxonomy_settings WHERE recipient_id = ?").bind(recipientId).run();

  const unique = new Map();
  for (const setting of settings.slice(0, 20)) {
    const taxonomyKey = cleanString(setting.taxonomyKey || setting.key, 80);
    const frequency = cleanString(setting.frequency, 32);
    if (!taxonomyKey || !FREQUENCIES.has(frequency)) continue;
    unique.set(taxonomyKey, frequency);
  }

  for (const [taxonomyKey, frequency] of unique) {
    await env.DB.prepare(
      "INSERT INTO recipient_taxonomy_settings (id, recipient_id, taxonomy_key, frequency) VALUES (?, ?, ?, ?)"
    ).bind(crypto.randomUUID(), recipientId, taxonomyKey, frequency).run();
  }
}

async function polarWebhook(request, env) {
  const bodyText = await request.text();
  if (!env.POLAR_WEBHOOK_SECRET) return json({ error: "Polar webhook secret is not configured." }, 501);
  const verified = await verifyPolarWebhook(request, bodyText, env.POLAR_WEBHOOK_SECRET);
  if (!verified) return json({ error: "Invalid webhook signature." }, 403);

  let event;
  try {
    event = JSON.parse(bodyText);
  } catch {
    return json({ error: "Invalid JSON." }, 400);
  }

  const eventId = request.headers.get("svix-id") || `${event.type}:${event.timestamp || Date.now()}`;
  const inserted = await env.DB.prepare(
    "INSERT OR IGNORE INTO polar_webhook_events (id, type, payload) VALUES (?, ?, ?)"
  ).bind(eventId, event.type || "unknown", bodyText).run();

  if (!inserted.meta?.changes) return json({ ok: true, duplicate: true }, 202);

  if ((event.type || "").startsWith("benefit_grant.")) {
    await upsertLicenseFromBenefitGrant(env, event.type, event.data || {});
  } else if (event.type === "subscription.revoked") {
    await revokeLicensesBySubscription(env, event.data?.id);
  }

  return json({ ok: true }, 202);
}

async function upsertLicenseFromBenefitGrant(env, eventType, data) {
  const benefitId = data.benefit_id || data.benefit?.id || "";
  const plan = planFromPolar(data.product_id, benefitId, data.benefit?.metadata?.plan);
  if (!plan) return;

  const customer = data.customer || {};
  const email = normalizeEmail(customer.email);
  const user = await findUserForPolarCustomer(env, customer.external_id, email);
  const status = eventType === "benefit_grant.revoked" || data.is_revoked ? "revoked" : data.is_granted ? "active" : "pending";
  const license = extractLicenseKey(data);

  if (customer.id) {
    await env.DB.prepare(
      `INSERT INTO polar_customers (id, user_id, email, name, external_id, metadata, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET
        user_id = COALESCE(excluded.user_id, polar_customers.user_id),
        email = excluded.email,
        name = excluded.name,
        external_id = excluded.external_id,
        metadata = excluded.metadata,
        updated_at = CURRENT_TIMESTAMP`
    ).bind(
      customer.id,
      user?.id || null,
      email || null,
      cleanString(customer.name || customer.billing_name, 160) || null,
      cleanString(customer.external_id, 160) || null,
      JSON.stringify(customer.metadata || {})
    ).run();
  }

  await env.DB.prepare(
    `INSERT INTO user_licenses (
      id, user_id, polar_customer_id, customer_email, benefit_grant_id, benefit_id,
      license_key_id, license_key_display, product_id, product_name, subscription_id,
      order_id, plan, status, granted_at, revoked_at, raw_properties, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(benefit_grant_id) DO UPDATE SET
      user_id = COALESCE(excluded.user_id, user_licenses.user_id),
      polar_customer_id = excluded.polar_customer_id,
      customer_email = excluded.customer_email,
      benefit_id = excluded.benefit_id,
      license_key_id = COALESCE(excluded.license_key_id, user_licenses.license_key_id),
      license_key_display = COALESCE(excluded.license_key_display, user_licenses.license_key_display),
      product_id = excluded.product_id,
      product_name = excluded.product_name,
      subscription_id = excluded.subscription_id,
      order_id = excluded.order_id,
      plan = excluded.plan,
      status = excluded.status,
      granted_at = COALESCE(excluded.granted_at, user_licenses.granted_at),
      revoked_at = excluded.revoked_at,
      raw_properties = excluded.raw_properties,
      updated_at = CURRENT_TIMESTAMP`
  ).bind(
    crypto.randomUUID(),
    user?.id || null,
    customer.id || data.customer_id || null,
    email || null,
    data.id,
    benefitId,
    license.id,
    license.display,
    data.product_id || null,
    plan.name,
    data.subscription_id || null,
    data.order_id || null,
    plan.key,
    status,
    data.granted_at || null,
    data.revoked_at || null,
    JSON.stringify(data.properties || {})
  ).run();
}

async function revokeLicensesBySubscription(env, subscriptionId) {
  if (!subscriptionId) return;
  await env.DB.prepare(
    "UPDATE user_licenses SET status = 'revoked', revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP WHERE subscription_id = ?"
  ).bind(subscriptionId).run();
}

async function linkLicensesForUser(env, userId) {
  const user = await env.DB.prepare("SELECT email FROM users WHERE id = ? LIMIT 1").bind(userId).first();
  const email = normalizeEmail(user?.email);
  if (!email) return;
  await env.DB.batch([
    env.DB.prepare("UPDATE polar_customers SET user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE lower(email) = ? AND user_id IS NULL")
      .bind(userId, email),
    env.DB.prepare("UPDATE user_licenses SET user_id = ?, updated_at = CURRENT_TIMESTAMP WHERE lower(customer_email) = ? AND user_id IS NULL")
      .bind(userId, email)
  ]);
}

async function findUserForPolarCustomer(env, externalId, email) {
  if (externalId) {
    const byExternalId = await env.DB.prepare("SELECT id FROM users WHERE id = ? LIMIT 1").bind(externalId).first();
    if (byExternalId) return byExternalId;
  }
  if (email) {
    return env.DB.prepare("SELECT id FROM users WHERE lower(email) = ? LIMIT 1").bind(email).first();
  }
  return null;
}

function planFromPolar(productId, benefitId, metadataPlan) {
  if (POLAR_PLANS[productId]) return POLAR_PLANS[productId];
  if (POLAR_BENEFITS[benefitId]) return POLAR_BENEFITS[benefitId];
  return planDetails(metadataPlan);
}

function planDetails(plan) {
  if (plan === "starter") return { key: "starter", name: "Care Text Starter", maxRecipients: 3 };
  if (plan === "family") return { key: "family", name: "Care Text Family", maxRecipients: 10 };
  return null;
}

function extractLicenseKey(data) {
  const sources = [data.properties, data.license_key, data.licenseKey].filter(Boolean);
  for (const source of sources) {
    const id = source.license_key_id || source.licenseKeyId || source.key_id || source.id;
    const display = source.display_key || source.license_key || source.licenseKey || source.key;
    if (id || display) return { id: id || null, display: display || null };
  }
  return { id: null, display: null };
}

async function verifyPolarWebhook(request, bodyText, secret) {
  const svixId = request.headers.get("svix-id");
  const svixTimestamp = request.headers.get("svix-timestamp");
  const svixSignature = request.headers.get("svix-signature");
  if (!svixId || !svixTimestamp || !svixSignature) return false;

  const timestamp = Number(svixTimestamp);
  if (!Number.isFinite(timestamp) || Math.abs((Date.now() / 1000) - timestamp) > 300) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    webhookSecretBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signedContent = `${svixId}.${svixTimestamp}.${bodyText}`;
  const signature = base64(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc(signedContent))));
  const expected = enc(signature);

  return svixSignature
    .split(" ")
    .map(part => part.trim())
    .filter(Boolean)
    .some(part => {
      const candidate = enc(part.replace(/^v1,/, ""));
      return timingSafeEqualBytes(candidate, expected);
    });
}

function webhookSecretBytes(secret) {
  const value = secret.startsWith("polar_whs_") ? secret.slice(10) : secret.startsWith("whsec_") ? secret.slice(6) : secret;
  try {
    return Uint8Array.from(atob(value), char => char.charCodeAt(0));
  } catch {
    return enc(secret);
  }
}

async function requireSession(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return json({ error: "Authentication required." }, 401);

  const tokenHash = await sha256Hex(token);
  const session = await env.DB.prepare(
    "SELECT user_id AS userId FROM sessions WHERE token_hash = ? AND expires_at > datetime('now') LIMIT 1"
  ).bind(tokenHash).first();
  if (!session) return json({ error: "Authentication required." }, 401);
  return session;
}

async function createSessionResponse(request, env, userId, payload, status = 200, extraHeaders = {}) {
  const token = randomToken(48);
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)"
  ).bind(crypto.randomUUID(), userId, tokenHash, expiresAt).run();

  const headers = {
    ...extraHeaders,
    "Set-Cookie": cookie(SESSION_COOKIE, token, {
      maxAge: SESSION_DAYS * 86400,
      httpOnly: true,
      sameSite: "Lax",
      secure: isHttps(new URL(request.url))
    })
  };

  if (status === 302) return new Response(null, { status, headers });
  return json(payload, status, headers);
}

async function loadUser(env, userId) {
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ? LIMIT 1").bind(userId).first();
  return user ? publicUser(user) : null;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    displayName: user.display_name,
    avatarUrl: user.avatar_url
  };
}

function normalizeRecipient(body) {
  return {
    displayName: cleanString(body.displayName, 100),
    relationship: cleanString(body.relationship, 80),
    phoneNumber: normalizePhone(body.phoneNumber),
    timezone: cleanString(body.timezone, 80) || "America/Denver"
  };
}

function normalizePhone(value) {
  return String(value || "").trim().replace(/[^\d+]/g, "").slice(0, 24);
}

function normalizeE164(value) {
  const phone = normalizePhone(value);
  return /^\+[1-9]\d{6,14}$/.test(phone) ? phone : "";
}

function normalizeEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : "";
}

function normalizeUsername(value) {
  const username = String(value || "").trim().toLowerCase();
  return /^[a-z0-9_]{3,32}$/.test(username) ? username : "";
}

function cleanString(value, max) {
  return String(value || "").trim().slice(0, max);
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function hashPassword(password, salt = randomToken(24)) {
  const key = await crypto.subtle.importKey("raw", enc(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc(salt), iterations: 210000, hash: "SHA-256" },
    key,
    256
  );
  return { hash: base64url(new Uint8Array(bits)), salt };
}

async function verifyPassword(password, salt, expectedHash) {
  const { hash } = await hashPassword(password, salt);
  return timingSafeEqual(hash, expectedHash);
}

function timingSafeEqual(a, b) {
  const left = enc(a);
  const right = enc(b);
  if (left.byteLength !== right.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < left.byteLength; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", enc(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function randomToken(bytes) {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return base64url(values);
}

function enc(value) {
  return new TextEncoder().encode(value);
}

async function awsSignedRequest({ method, url, region, service, accessKeyId, secretAccessKey, sessionToken, body }) {
  const target = new URL(url);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256Hex(body);

  const headers = {
    "Content-Type": "application/json",
    "Host": target.host,
    "X-Amz-Content-Sha256": payloadHash,
    "X-Amz-Date": amzDate
  };
  if (sessionToken) headers["X-Amz-Security-Token"] = sessionToken;

  const signedHeaderNames = Object.keys(headers).map(name => name.toLowerCase()).sort();
  const canonicalHeaders = signedHeaderNames
    .map(name => `${name}:${headers[headerName(headers, name)].toString().trim().replace(/\s+/g, " ")}\n`)
    .join("");
  const signedHeaders = signedHeaderNames.join(";");
  const canonicalRequest = [
    method,
    target.pathname,
    target.searchParams.toString(),
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest)
  ].join("\n");
  const signingKey = await awsSigningKey(secretAccessKey, dateStamp, region, service);
  const signature = bytesToHex(new Uint8Array(await crypto.subtle.sign("HMAC", signingKey, enc(stringToSign))));

  headers.Authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { method, headers, body };
}

function headerName(headers, lowercaseName) {
  return Object.keys(headers).find(name => name.toLowerCase() === lowercaseName);
}

async function awsSigningKey(secretAccessKey, dateStamp, region, service) {
  const dateKey = await hmacBytes(enc(`AWS4${secretAccessKey}`), dateStamp);
  const dateRegionKey = await hmacBytes(dateKey, region);
  const dateRegionServiceKey = await hmacBytes(dateRegionKey, service);
  const signingKeyBytes = await hmacBytes(dateRegionServiceKey, "aws4_request");
  return crypto.subtle.importKey("raw", signingKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function hmacBytes(keyBytes, value) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc(value)));
}

function bytesToHex(bytes) {
  return [...bytes].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function timingSafeEqualBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < left.byteLength; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

function googleRedirectUri(url, env) {
  return `${url.origin}${env.GOOGLE_REDIRECT_PATH || "/api/auth/google/callback"}`;
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return "";
}

function cookie(name, value, options = {}) {
  const parts = [`${name}=${value}`, "Path=/"];
  if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push("Secure");
  return parts.join("; ");
}

function expireCookie(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`;
}

function isHttps(url) {
  return url.protocol === "https:";
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers
    }
  });
}

function redirect(location, headers = {}) {
  return new Response(null, { status: 302, headers: { Location: location, ...headers } });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}
