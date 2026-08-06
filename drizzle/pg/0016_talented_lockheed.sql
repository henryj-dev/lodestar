CREATE TABLE "service_entitlements" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"service_type" text NOT NULL,
	"service_ref_id" text NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"description" text,
	"display_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_service_entitlements" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"assignment_id" text NOT NULL,
	"service_entitlement_id" text NOT NULL,
	"granted_by" text,
	"granted_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp (3) with time zone,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "service_entitlements" ADD CONSTRAINT "service_entitlements_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_service_entitlements" ADD CONSTRAINT "user_service_entitlements_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_service_entitlements" ADD CONSTRAINT "user_service_entitlements_assignment_fk" FOREIGN KEY ("assignment_id") REFERENCES "public"."user_service_assignments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_service_entitlements" ADD CONSTRAINT "user_service_entitlements_entitlement_fk" FOREIGN KEY ("service_entitlement_id") REFERENCES "public"."service_entitlements"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "service_entitlements_service_key_uidx" ON "service_entitlements" USING btree ("service_type","service_ref_id","key");--> statement-breakpoint
CREATE INDEX "service_entitlements_tenant_service_idx" ON "service_entitlements" USING btree ("tenant_id","service_type","service_ref_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_service_entitlements_assignment_ent_uidx" ON "user_service_entitlements" USING btree ("assignment_id","service_entitlement_id");--> statement-breakpoint
CREATE INDEX "user_service_entitlements_tenant_ent_idx" ON "user_service_entitlements" USING btree ("tenant_id","service_entitlement_id");