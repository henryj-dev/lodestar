CREATE TABLE `oidc_client_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`session_id` text NOT NULL,
	`client_id` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`session_id`) REFERENCES `sessions`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oidc_client_sessions_session_client_uidx` ON `oidc_client_sessions` (`session_id`,`client_id`);--> statement-breakpoint
CREATE INDEX `oidc_client_sessions_tenant_session_idx` ON `oidc_client_sessions` (`tenant_id`,`session_id`);