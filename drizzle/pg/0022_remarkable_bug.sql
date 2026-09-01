CREATE TABLE "client_terms" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"client_type" text NOT NULL,
	"client_ref_id" text NOT NULL,
	"terms_key" text NOT NULL,
	"created_at" timestamp (3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "terms_documents" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"key" text NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"locale" text DEFAULT 'ko' NOT NULL,
	"title" text NOT NULL,
	"body" text NOT NULL,
	"required" boolean DEFAULT true NOT NULL,
	"published_at" timestamp (3) with time zone,
	"display_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp (3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_client_consents" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"user_id" text NOT NULL,
	"client_type" text NOT NULL,
	"client_ref_id" text NOT NULL,
	"granted_scopes" text DEFAULT '' NOT NULL,
	"granted_at" timestamp (3) with time zone NOT NULL,
	"revoked_at" timestamp (3) with time zone
);
--> statement-breakpoint
CREATE TABLE "user_term_agreements" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"user_id" text NOT NULL,
	"terms_key" text NOT NULL,
	"version" integer NOT NULL,
	"locale" text NOT NULL,
	"agreed" boolean DEFAULT true NOT NULL,
	"agreed_at" timestamp (3) with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "oidc_clients" ADD COLUMN "optional_scopes" text;--> statement-breakpoint
ALTER TABLE "client_terms" ADD CONSTRAINT "client_terms_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "terms_documents" ADD CONSTRAINT "terms_documents_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_client_consents" ADD CONSTRAINT "user_client_consents_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_client_consents" ADD CONSTRAINT "user_client_consents_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_term_agreements" ADD CONSTRAINT "user_term_agreements_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_term_agreements" ADD CONSTRAINT "user_term_agreements_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "client_terms_unique" ON "client_terms" USING btree ("tenant_id","client_type","client_ref_id","terms_key");--> statement-breakpoint
CREATE INDEX "client_terms_lookup_idx" ON "client_terms" USING btree ("tenant_id","client_type","client_ref_id");--> statement-breakpoint
CREATE UNIQUE INDEX "terms_documents_unique" ON "terms_documents" USING btree ("tenant_id","key","version","locale");--> statement-breakpoint
CREATE INDEX "terms_documents_tenant_idx" ON "terms_documents" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX "user_client_consents_lookup_idx" ON "user_client_consents" USING btree ("tenant_id","user_id","client_type","client_ref_id");--> statement-breakpoint
CREATE INDEX "user_client_consents_user_idx" ON "user_client_consents" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_term_agreements_unique" ON "user_term_agreements" USING btree ("user_id","terms_key","version");--> statement-breakpoint
CREATE INDEX "user_term_agreements_user_idx" ON "user_term_agreements" USING btree ("tenant_id","user_id");