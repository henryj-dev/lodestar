CREATE TABLE `oidc_client_sessions` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`session_id` varchar(64) NOT NULL,
	`client_id` varchar(255) NOT NULL,
	`created_at` datetime(3) NOT NULL DEFAULT (CURRENT_TIMESTAMP(3)),
	CONSTRAINT `oidc_client_sessions_id` PRIMARY KEY(`id`),
	CONSTRAINT `oidc_client_sessions_session_client_uidx` UNIQUE(`session_id`,`client_id`)
);
--> statement-breakpoint
ALTER TABLE `oidc_client_sessions` ADD CONSTRAINT `oidc_client_sessions_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `oidc_client_sessions` ADD CONSTRAINT `oidc_client_sessions_session_id_sessions_id_fk` FOREIGN KEY (`session_id`) REFERENCES `sessions`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `oidc_client_sessions_tenant_session_idx` ON `oidc_client_sessions` (`tenant_id`,`session_id`);