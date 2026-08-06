CREATE TABLE `service_api_tokens` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`token_hash` varchar(255) NOT NULL,
	`token_prefix` varchar(64) NOT NULL,
	`scopes` text NOT NULL,
	`created_by` text,
	`created_at` datetime(3) NOT NULL DEFAULT (CURRENT_TIMESTAMP(3)),
	`expires_at` datetime(3),
	`last_used_at` datetime(3),
	CONSTRAINT `service_api_tokens_id` PRIMARY KEY(`id`),
	CONSTRAINT `service_api_tokens_token_hash_uidx` UNIQUE(`token_hash`)
);
--> statement-breakpoint
ALTER TABLE `service_api_tokens` ADD CONSTRAINT `service_api_tokens_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `service_api_tokens_tenant_idx` ON `service_api_tokens` (`tenant_id`);