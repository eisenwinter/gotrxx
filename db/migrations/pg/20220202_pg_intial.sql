CREATE SCHEMA gotrxx;

CREATE TABLE gotrxx.audit_logs (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    event JSON NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE gotrxx.users (
    id uuid NOT NULL PRIMARY KEY,
    email TEXT UNIQUE,
    email_confirmed TIMESTAMP,
    phone TEXT UNIQUE,
    phone_confirmed TIMESTAMP,
    mfa BOOLEAN DEFAULT false,
    mfa_secret TEXT,
    mfa_recovery_key TEXT,
    pending_otp BOOLEAN DEFAULT false,
    lockout_till TIMESTAMP,
    banned_on TIMESTAMP,
    "password" TEXT,
    current_failure_count INTEGER NOT NULL DEFAULT 0,
    recovery_token TEXT,
    recovery_token_created TIMESTAMP,
    confirm_token TEXT,
    confirm_token_created TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP
);


CREATE TABLE gotrxx.user_invites (
    id SERIAL PRIMARY KEY,
    email TEXT,
    code TEXT NOT NULL,
    sent_at TIMESTAMP,
    consumed_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);


CREATE TABLE gotrxx.roles (
    id SERIAL PRIMARY KEY,
    "name" TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);



CREATE TABLE gotrxx.user_roles (
     role_id integer NOT NULL,
     user_id uuid NOT NULL,
    PRIMARY KEY (role_id, user_id),
    FOREIGN KEY(user_id) REFERENCES gotrxx.users(id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES gotrxx.roles(id) ON DELETE CASCADE
);


CREATE TABLE gotrxx.user_invite_roles (
     role_id integer NOT NULL,
     user_invite_id integer NOT NULL,
    PRIMARY KEY (role_id, user_invite_id),
    FOREIGN KEY(user_invite_id) REFERENCES gotrxx.user_invites(id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES gotrxx.roles(id) ON DELETE CASCADE
);



CREATE table gotrxx.applications (
    id SERIAL PRIMARY KEY,
    client_id text UNIQUE NOT NULL, 
    client_secret text,
    "name" text,
    "type" integer NOT NULL,
    confidentiality text NOT NULL,
    properties JSON,
    retired_on TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP
);



CREATE TABLE gotrxx.user_invite_applications (
    application_id integer NOT NULL,
    user_invite_id integer NOT NULL,
    scopes text NOT NULL DEFAULT '',
    PRIMARY KEY (application_id, user_invite_id),
    FOREIGN KEY(user_invite_id) REFERENCES gotrxx.user_invites(id) ON DELETE CASCADE,
    FOREIGN KEY(application_id) REFERENCES gotrxx.applications(id) ON DELETE CASCADE
);


CREATE table gotrxx.authorizations (
    id uuid NOT NULL PRIMARY KEY ,
    application_id integer NOT NULL,
    user_id uuid NOT NULL,
    properties JSON,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    FOREIGN KEY(application_id) REFERENCES gotrxx.applications(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES gotrxx.users(id) ON DELETE CASCADE
);


CREATE TABLE gotrxx.tokens (
    id SERIAL PRIMARY KEY,
    application_id integer NOT NULL,
    authorization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_type text NOT NULL,
    token text NOT NULL,
    properties JSON,
    redeemed_at TIMESTAMP,
    revoked_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    FOREIGN KEY(application_id) REFERENCES gotrxx.applications(id) ON DELETE CASCADE,
    FOREIGN KEY(authorization_id) REFERENCES gotrxx.authorizations(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES gotrxx.users(id) ON DELETE CASCADE
);


CREATE UNIQUE INDEX ix_users_email ON gotrxx.users(email);
CREATE INDEX ix_users_confirm_token ON gotrxx.users(confirm_token);

CREATE INDEX ix_roles_name ON gotrxx.roles("name");

CREATE INDEX ix_user_invites_code ON gotrxx.user_invites(code);
CREATE UNIQUE INDEX ix_user_invites_mail_code ON gotrxx.user_invites(code, email);

CREATE INDEX ix_applications_client_id ON gotrxx.applications(client_id);
CREATE INDEX ix_applications_cid_ret ON gotrxx.applications(client_id, retired_on);
CREATE INDEX ix_authorizations_uid_rev ON gotrxx.authorizations(user_id, revoked_at);
CREATE INDEX ix_tokens_token_tt  ON gotrxx.tokens(token_type, token);
CREATE INDEX ix_tokens_app_id  ON gotrxx.tokens(application_id);
CREATE INDEX ix_tokens_rev_red_token_tt_exp ON gotrxx.tokens(token_type, token, revoked_at, redeemed_at, expires_at);

INSERT INTO gotrxx.roles (name, created_at) VALUES ('admin', NOW());
INSERT INTO gotrxx.roles (name, created_at) VALUES ('inviter', NOW());

INSERT INTO gotrxx.applications (client_id, name, type, confidentiality, properties, created_at) VALUES ('$.gotrxx','Gotrxx itself', 1, 'private', '{"allowed_flows": [], "scopes": [], "redirect_uris": []}', NOW());
INSERT INTO gotrxx.applications (client_id, name, type, confidentiality, properties, created_at) VALUES ('netlify-gotrue','Gotrue Wrapper', 1, 'public', '{"allowed_flows": ["password", "refresh_token"], "scopes": []}', NOW());
