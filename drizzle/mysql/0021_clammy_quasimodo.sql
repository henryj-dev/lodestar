ALTER TABLE `oidc_clients` ADD `require_mfa` boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `oidc_clients` ADD `reauth_policy` varchar(32) DEFAULT 'full' NOT NULL;--> statement-breakpoint
ALTER TABLE `saml_sps` ADD `require_mfa` boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `saml_sps` ADD `reauth_policy` varchar(32) DEFAULT 'full' NOT NULL;--> statement-breakpoint
ALTER TABLE `sessions` ADD `auth_time` datetime(3);