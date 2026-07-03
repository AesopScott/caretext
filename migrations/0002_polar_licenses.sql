PRAGMA foreign_keys = ON;

CREATE TABLE polar_customers (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  email TEXT,
  name TEXT,
  external_id TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX polar_customers_user_id_idx ON polar_customers(user_id);
CREATE INDEX polar_customers_email_idx ON polar_customers(email);

CREATE TABLE user_licenses (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  polar_customer_id TEXT,
  customer_email TEXT,
  benefit_grant_id TEXT NOT NULL UNIQUE,
  benefit_id TEXT NOT NULL,
  license_key_id TEXT,
  license_key_display TEXT,
  product_id TEXT,
  product_name TEXT,
  subscription_id TEXT,
  order_id TEXT,
  plan TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'pending')),
  granted_at TEXT,
  revoked_at TEXT,
  raw_properties TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX user_licenses_user_id_idx ON user_licenses(user_id);
CREATE INDEX user_licenses_customer_idx ON user_licenses(polar_customer_id);
CREATE INDEX user_licenses_subscription_idx ON user_licenses(subscription_id);
CREATE INDEX user_licenses_plan_idx ON user_licenses(plan);

CREATE TABLE polar_webhook_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
