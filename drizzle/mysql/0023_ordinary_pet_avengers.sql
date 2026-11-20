CREATE TABLE `retired_subjects` (
	`id` varchar(64) NOT NULL,
	`tenant_id` varchar(64) NOT NULL,
	`provider` varchar(255) NOT NULL,
	`subject` varchar(255) NOT NULL,
	`issuer` text,
	`retired_at` datetime(3) NOT NULL DEFAULT (CURRENT_TIMESTAMP(3)),
	CONSTRAINT `retired_subjects_id` PRIMARY KEY(`id`),
	CONSTRAINT `retired_subjects_tenant_provider_subject_uidx` UNIQUE(`tenant_id`,`provider`,`subject`)
);
--> statement-breakpoint
ALTER TABLE `retired_subjects` ADD CONSTRAINT `retired_subjects_tenant_id_tenants_id_fk` FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `audit_events_created_idx` ON `audit_events` (`created_at`);