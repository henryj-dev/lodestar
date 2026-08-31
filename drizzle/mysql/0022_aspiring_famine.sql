CREATE TABLE `client_terms` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`client_type` varchar(64) NOT NULL,
	`client_ref_id` varchar(64) NOT NULL,
	`terms_key` varchar(128) NOT NULL,
	`created_at` datetime(3) NOT NULL,
	CONSTRAINT `client_terms_id` PRIMARY KEY(`id`),
	CONSTRAINT `client_terms_unique` UNIQUE(`tenant_id`,`client_type`,`client_ref_id`,`terms_key`)
);
--> statement-breakpoint
CREATE TABLE `terms_documents` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`key` varchar(128) NOT NULL,
	`version` int NOT NULL DEFAULT 1,
	`locale` varchar(16) NOT NULL DEFAULT 'ko',
	`title` varchar(255) NOT NULL,
	`body` text NOT NULL,
	`required` boolean NOT NULL DEFAULT true,
	`published_at` datetime(3),
	`display_order` int NOT NULL DEFAULT 0,
	`created_at` datetime(3) NOT NULL,
	CONSTRAINT `terms_documents_id` PRIMARY KEY(`id`),
	CONSTRAINT `terms_documents_unique` UNIQUE(`tenant_id`,`key`,`version`,`locale`)
);
--> statement-breakpoint
CREATE TABLE `user_client_consents` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`user_id` varchar(64) NOT NULL,
	`client_type` varchar(64) NOT NULL,
	`client_ref_id` varchar(64) NOT NULL,
	`granted_scopes` text NOT NULL DEFAULT (''),
	`granted_at` datetime(3) NOT NULL,
	`revoked_at` datetime(3),
	CONSTRAINT `user_client_consents_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `user_term_agreements` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`user_id` varchar(64) NOT NULL,
	`terms_key` varchar(128) NOT NULL,
	`version` int NOT NULL,
	`locale` varchar(16) NOT NULL,
	`agreed` boolean NOT NULL DEFAULT true,
	`agreed_at` datetime(3) NOT NULL,
	CONSTRAINT `user_term_agreements_id` PRIMARY KEY(`id`),
	CONSTRAINT `user_term_agreements_unique` UNIQUE(`user_id`,`terms_key`,`version`)
);
--> statement-breakpoint
ALTER TABLE `oidc_clients` ADD `optional_scopes` text;--> statement-breakpoint
ALTER TABLE `client_terms` ADD CONSTRAINT `client_terms_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `terms_documents` ADD CONSTRAINT `terms_documents_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `user_client_consents` ADD CONSTRAINT `user_client_consents_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `user_client_consents` ADD CONSTRAINT `user_client_consents_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `user_term_agreements` ADD CONSTRAINT `user_term_agreements_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `user_term_agreements` ADD CONSTRAINT `user_term_agreements_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `client_terms_lookup_idx` ON `client_terms` (`tenant_id`,`client_type`,`client_ref_id`);--> statement-breakpoint
CREATE INDEX `terms_documents_tenant_idx` ON `terms_documents` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `user_client_consents_lookup_idx` ON `user_client_consents` (`tenant_id`,`user_id`,`client_type`,`client_ref_id`);--> statement-breakpoint
CREATE INDEX `user_client_consents_user_idx` ON `user_client_consents` (`user_id`);--> statement-breakpoint
CREATE INDEX `user_term_agreements_user_idx` ON `user_term_agreements` (`tenant_id`,`user_id`);