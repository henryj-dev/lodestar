CREATE TABLE `service_entitlements` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`service_type` text NOT NULL,
	`service_ref_id` text NOT NULL,
	`key` text NOT NULL,
	`label` text NOT NULL,
	`description` text,
	`display_order` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `service_entitlements_service_key_uidx` ON `service_entitlements` (`service_type`,`service_ref_id`,`key`);--> statement-breakpoint
CREATE INDEX `service_entitlements_tenant_service_idx` ON `service_entitlements` (`tenant_id`,`service_type`,`service_ref_id`);--> statement-breakpoint
CREATE TABLE `user_service_entitlements` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`assignment_id` text NOT NULL,
	`service_entitlement_id` text NOT NULL,
	`granted_by` text,
	`granted_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`expires_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`assignment_id`) REFERENCES `user_service_assignments`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`service_entitlement_id`) REFERENCES `service_entitlements`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_service_entitlements_assignment_ent_uidx` ON `user_service_entitlements` (`assignment_id`,`service_entitlement_id`);--> statement-breakpoint
CREATE INDEX `user_service_entitlements_tenant_ent_idx` ON `user_service_entitlements` (`tenant_id`,`service_entitlement_id`);