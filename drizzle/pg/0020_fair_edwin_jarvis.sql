ALTER TABLE "identity_providers" ADD COLUMN "slug" text;--> statement-breakpoint
CREATE UNIQUE INDEX "idp_tenant_slug_uidx" ON "identity_providers" USING btree ("tenant_id","slug");