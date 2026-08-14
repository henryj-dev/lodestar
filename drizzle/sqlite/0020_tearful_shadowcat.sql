ALTER TABLE `identity_providers` ADD `slug` text;--> statement-breakpoint
CREATE UNIQUE INDEX `idp_tenant_slug_uidx` ON `identity_providers` (`tenant_id`,`slug`);