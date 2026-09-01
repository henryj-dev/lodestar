CREATE TABLE `client_terms` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`client_type` text NOT NULL,
	`client_ref_id` text NOT NULL,
	`terms_key` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `client_terms_unique` ON `client_terms` (`tenant_id`,`client_type`,`client_ref_id`,`terms_key`);--> statement-breakpoint
CREATE INDEX `client_terms_lookup_idx` ON `client_terms` (`tenant_id`,`client_type`,`client_ref_id`);--> statement-breakpoint
CREATE TABLE `terms_documents` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`key` text NOT NULL,
	`version` integer DEFAULT 1 NOT NULL,
	`locale` text DEFAULT 'ko' NOT NULL,
	`title` text NOT NULL,
	`body` text NOT NULL,
	`required` integer DEFAULT true NOT NULL,
	`published_at` integer,
	`display_order` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `terms_documents_unique` ON `terms_documents` (`tenant_id`,`key`,`version`,`locale`);--> statement-breakpoint
CREATE INDEX `terms_documents_tenant_idx` ON `terms_documents` (`tenant_id`);--> statement-breakpoint
CREATE TABLE `user_client_consents` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`user_id` text NOT NULL,
	`client_type` text NOT NULL,
	`client_ref_id` text NOT NULL,
	`granted_scopes` text DEFAULT '' NOT NULL,
	`granted_at` integer NOT NULL,
	`revoked_at` integer,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `user_client_consents_lookup_idx` ON `user_client_consents` (`tenant_id`,`user_id`,`client_type`,`client_ref_id`);--> statement-breakpoint
CREATE INDEX `user_client_consents_user_idx` ON `user_client_consents` (`user_id`);--> statement-breakpoint
CREATE TABLE `user_term_agreements` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`user_id` text NOT NULL,
	`terms_key` text NOT NULL,
	`version` integer NOT NULL,
	`locale` text NOT NULL,
	`agreed` integer DEFAULT true NOT NULL,
	`agreed_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_term_agreements_unique` ON `user_term_agreements` (`user_id`,`terms_key`,`version`);--> statement-breakpoint
CREATE INDEX `user_term_agreements_user_idx` ON `user_term_agreements` (`tenant_id`,`user_id`);--> statement-breakpoint
ALTER TABLE `oidc_clients` ADD `optional_scopes` text;