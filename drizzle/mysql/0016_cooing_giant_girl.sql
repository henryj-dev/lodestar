CREATE TABLE `service_entitlements` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`service_type` varchar(64) NOT NULL,
	`service_ref_id` varchar(64) NOT NULL,
	`key` varchar(255) NOT NULL,
	`label` varchar(255) NOT NULL,
	`description` text,
	`display_order` int NOT NULL DEFAULT 0,
	`created_at` datetime(3) NOT NULL DEFAULT (CURRENT_TIMESTAMP(3)),
	`updated_at` datetime(3) NOT NULL DEFAULT (CURRENT_TIMESTAMP(3)),
	CONSTRAINT `service_entitlements_id` PRIMARY KEY(`id`),
	CONSTRAINT `service_entitlements_service_key_uidx` UNIQUE(`service_type`,`service_ref_id`,`key`)
);
--> statement-breakpoint
CREATE TABLE `user_service_entitlements` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`assignment_id` varchar(64) NOT NULL,
	`service_entitlement_id` varchar(64) NOT NULL,
	`granted_by` text,
	`granted_at` datetime(3) NOT NULL DEFAULT (CURRENT_TIMESTAMP(3)),
	`expires_at` datetime(3),
	`created_at` datetime(3) NOT NULL DEFAULT (CURRENT_TIMESTAMP(3)),
	CONSTRAINT `user_service_entitlements_id` PRIMARY KEY(`id`),
	CONSTRAINT `user_service_entitlements_assignment_ent_uidx` UNIQUE(`assignment_id`,`service_entitlement_id`)
);
--> statement-breakpoint
ALTER TABLE `service_entitlements` ADD CONSTRAINT `service_entitlements_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `user_service_entitlements` ADD CONSTRAINT `user_service_entitlements_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `user_service_entitlements` ADD CONSTRAINT `user_service_entitlements_assignment_fk` FOREIGN KEY (`assignment_id`) REFERENCES `user_service_assignments`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `user_service_entitlements` ADD CONSTRAINT `user_service_entitlements_entitlement_fk` FOREIGN KEY (`service_entitlement_id`) REFERENCES `service_entitlements`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `service_entitlements_tenant_service_idx` ON `service_entitlements` (`tenant_id`,`service_type`,`service_ref_id`);--> statement-breakpoint
CREATE INDEX `user_service_entitlements_tenant_ent_idx` ON `user_service_entitlements` (`tenant_id`,`service_entitlement_id`);