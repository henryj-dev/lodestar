ALTER TABLE `identity_providers` ADD `slug` varchar(64);--> statement-breakpoint
ALTER TABLE `identity_providers` ADD CONSTRAINT `idp_tenant_slug_uidx` UNIQUE(`tenant_id`,`slug`);