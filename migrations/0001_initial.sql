PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  username TEXT UNIQUE,
  password_hash TEXT,
  password_salt TEXT,
  display_name TEXT,
  avatar_url TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_profiles (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  first_name TEXT,
  last_name TEXT,
  timezone TEXT NOT NULL DEFAULT 'America/Denver',
  phone_number TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(provider, provider_user_id)
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE taxonomy_categories (
  key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  message_mode TEXT NOT NULL CHECK (message_mode IN ('direct', 'non_direct')),
  use_case TEXT NOT NULL
);

CREATE TABLE recipients (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL,
  relationship TEXT,
  phone_number TEXT NOT NULL,
  timezone TEXT NOT NULL DEFAULT 'America/Denver',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, phone_number)
);

CREATE INDEX recipients_user_id_idx ON recipients(user_id);

CREATE TABLE recipient_taxonomy_settings (
  id TEXT PRIMARY KEY,
  recipient_id TEXT NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
  taxonomy_key TEXT NOT NULL REFERENCES taxonomy_categories(key),
  frequency TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly', 'every_other_week')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(recipient_id, taxonomy_key)
);

CREATE INDEX recipient_taxonomy_recipient_idx ON recipient_taxonomy_settings(recipient_id);

INSERT INTO taxonomy_categories (key, name, message_mode, use_case) VALUES
  ('morning_start', 'Morning Start', 'direct', 'Encouragement for beginning the day.'),
  ('end_of_day_reflection', 'End-of-Day Reflection', 'direct', 'Gentle messages for closing the day.'),
  ('during_treatment', 'During Treatment', 'direct', 'Support while someone is actively in care or treatment.'),
  ('scan_or_test_anxiety', 'Scan or Test Anxiety', 'direct', 'Reassurance before tests, scans, lab work, or results.'),
  ('before_surgery_or_procedure', 'Before Surgery or Procedure', 'direct', 'Calm and courage before a medical procedure.'),
  ('recovery_milestones', 'Recovery Milestones', 'direct', 'Recognition of progress, healing, and next steps.'),
  ('pain_or_fatigue_days', 'Pain or Fatigue Days', 'direct', 'Support for physically difficult days.'),
  ('feeling_isolated', 'Feeling Isolated', 'direct', 'Reminders of presence, connection, and being remembered.'),
  ('family_and_caregiver_support', 'Family and Caregiver Support', 'direct', 'Encouragement for caregivers and family members.'),
  ('faith_based_hope', 'Faith-Based Hope', 'direct', 'Spiritually grounded messages for recipients who welcome faith language.'),
  ('nonreligious_hope', 'Nonreligious Hope', 'direct', 'Hopeful messages without religious or spiritual framing.'),
  ('grief_and_loss', 'Grief and Loss', 'direct', 'Tender support around loss, sadness, or mourning.'),
  ('uncertainty_about_the_future', 'Uncertainty About the Future', 'direct', 'Steadiness when the path ahead is unclear.'),
  ('celebrating_small_wins', 'Celebrating Small Wins', 'direct', 'Recognition of small victories and meaningful progress.'),
  ('self_compassion', 'Self-Compassion', 'direct', 'Permission to be gentle with oneself.'),
  ('practical_grounding', 'Practical Grounding', 'direct', 'Short, calming prompts for breath, attention, and the present moment.'),
  ('hard_conversations', 'Hard Conversations', 'direct', 'Courage and care around difficult talks.'),
  ('long_haul_perseverance', 'Long-Haul Perseverance', 'direct', 'Encouragement for ongoing, slow, or tiring seasons.'),
  ('community_and_belonging', 'Community and Belonging', 'direct', 'Reminders that care can come from a wider circle.'),
  ('everyday_beauty', 'Everyday Beauty', 'non_direct', 'Ambient inspiration from ordinary life, nature, seasons, music, light, gratitude, and small moments of goodness.');
