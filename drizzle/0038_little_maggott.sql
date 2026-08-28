ALTER TABLE `oidc_clients` ADD `require_mfa` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `oidc_clients` ADD `reauth_policy` text DEFAULT 'full' NOT NULL;--> statement-breakpoint
ALTER TABLE `saml_sps` ADD `require_mfa` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `saml_sps` ADD `reauth_policy` text DEFAULT 'full' NOT NULL;--> statement-breakpoint
ALTER TABLE `sessions` ADD `auth_time` integer;