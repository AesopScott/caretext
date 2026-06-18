const SESSION_COOKIE = "ct_session";
const GOOGLE_STATE_COOKIE = "ct_google_state";
const SESSION_DAYS = 30;
const MAX_RECIPIENTS = 10;
const FREQUENCIES = new Set(["daily", "weekly", "every_other_week"]);

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

  const session = await requireSession(request, env);
  if (session instanceof Response) return session;

  if (route === "GET /api/profile") return getProfile(env, session.userId);
  if (route === "PUT /api/profile") return updateProfile(request, env, session.userId);
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

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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
