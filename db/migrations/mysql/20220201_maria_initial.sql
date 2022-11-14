SET character_set_client = utf8;
CREATE TABLE `audit_logs` (
    `id` integer NOT NULL AUTO_INCREMENT,
    `event_type` text NOT NULL,
    `event` JSON NOT NULL,
    `created_at` datetime NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `users` (
    `id` char(36) NOT NULL,
    `email` varchar(512) UNIQUE,
    `email_confirmed` datetime,
    `phone` varchar(255) UNIQUE,
    `phone_confirmed` datetime,
    `mfa` BOOLEAN DEFAULT 0,
    `mfa_secret` varchar(255),
    `mfa_recovery_key` text,
    `pending_otp` BOOLEAN DEFAULT 0,
    `lockout_till` datetime,
    `banned_on` datetime,
    `password` varchar(255),
    `current_failure_count` integer NOT NULL DEFAULT 0,
    `recovery_token` varchar(255),
    `recovery_token_created` datetime,
    `confirm_token` varchar(255),
    `confirm_token_created` datetime,
    `created_at` datetime NOT NULL,
    `updated_at` datetime,
    PRIMARY KEY (`id`) 
);


CREATE UNIQUE INDEX ix_users_email ON users(`email`(255));
CREATE INDEX ix_users_confirm_token ON users(`confirm_token`(255));

CREATE TABLE `user_invites` (
    `id` integer NOT NULL AUTO_INCREMENT,
    `email` varchar(512),
    `code` text NOT NULL,
    `sent_at` datetime,
    `consumed_at` datetime,
    `expires_at` datetime NOT NULL,
    `created_at` datetime NOT NULL,
    PRIMARY KEY (`id`)
);
CREATE INDEX ix_user_invites_code ON user_invites(`code`(255));
CREATE UNIQUE INDEX ix_user_invites_mail_code ON user_invites(`code`(255), `email`(255));

CREATE TABLE `roles` (
    `id` integer NOT NULL AUTO_INCREMENT,
    `name` varchar(255) NOT NULL,
    `created_at` datetime NOT NULL,
    PRIMARY KEY (`id`)
);
CREATE INDEX ix_roles_name ON roles(`name`(255));


CREATE TABLE `user_roles` (
     `role_id` integer NOT NULL,
     `user_id` char(36) NOT NULL,
    PRIMARY KEY (`role_id`, `user_id`),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
);


CREATE TABLE `user_invite_roles` (
     `role_id` integer NOT NULL,
     `user_invite_id` integer NOT NULL,
    PRIMARY KEY (`role_id`, `user_invite_id`),
    FOREIGN KEY(user_invite_id) REFERENCES user_invites(id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
);



CREATE table `applications` (
    `id` integer NOT NULL AUTO_INCREMENT,
    `client_id` text UNIQUE NOT NULL, 
    `client_secret` text,
    `name` text,
    `type` integer NOT NULL,
    `confidentiality` text NOT NULL,
    `properties` JSON,
    `retired_on` datetime,
    `created_at` datetime NOT NULL,
    `updated_at` datetime,
    PRIMARY KEY (`id`)
);
CREATE INDEX ix_applications_client_id ON applications(`client_id`(255));
CREATE INDEX ix_applications_cid_ret ON applications(`client_id`(255), `retired_on`);



CREATE TABLE `user_invite_applications` (
     `application_id` integer NOT NULL,
     `user_invite_id` integer NOT NULL,
     `scopes` text NOT NULL DEFAULT '',
    PRIMARY KEY (`application_id`, `user_invite_id`),
    FOREIGN KEY(user_invite_id) REFERENCES user_invites(id) ON DELETE CASCADE,
    FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE
);


CREATE table `authorizations` (
    `id` char(36) NOT NULL,
    `application_id` integer NOT NULL,
    `user_id` char(36) NOT NULL,
    `properties` JSON,
    `revoked_at` datetime,
    `created_at` datetime NOT NULL,
    `updated_at` datetime,
    PRIMARY KEY (`id`),
    FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX ix_authorizations_uid_rev ON authorizations(`user_id`, `revoked_at`);

CREATE TABLE `tokens` (
    `id` integer NOT NULL AUTO_INCREMENT,
    `application_id` integer NOT NULL,
    `authorization_id` char(36) NOT NULL,
    `user_id` char(36) NOT NULL,
    `token_type` text NOT NULL,
    `token` text NOT NULL,
    `properties` JSON,
    `redeemed_at` datetime,
    `revoked_at` datetime,
    `expires_at` datetime NOT NULL,
    `created_at` datetime NOT NULL,
    `updated_at` datetime,
    PRIMARY KEY (`id`),
    FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY(authorization_id) REFERENCES authorizations(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX ix_tokens_token_tt  ON tokens(`token_type`(255), `token`(255));
CREATE INDEX ix_tokens_app_id  ON tokens(`application_id`);
CREATE INDEX ix_tokens_rev_red_token_tt_exp ON tokens(`token_type`(255), `token`(255), `revoked_at`, `redeemed_at`, `expires_at`);

INSERT INTO `roles` (`name`, `created_at`) VALUES ('admin', NOW());
INSERT INTO `roles` (`name`, `created_at`) VALUES ('inviter', NOW());

INSERT INTO `applications` (`client_id`, `name`, `type`, `confidentiality`, `properties`, `created_at`) VALUES ('$.gotrxx','Gotrxx itself', 1, 'private', '{"allowed_flows": [], "scopes": [], "redirect_uris": []}', NOW());
INSERT INTO `applications` (`client_id`, `name`, `type`, `confidentiality`, `properties`, `created_at`) VALUES ('netlify-gotrue','Gotrue Wrapper', 1, 'public', '{"allowed_flows": ["password", "refresh_token"], "scopes": []}', NOW());
