CREATE TABLE "service_api_tokens" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"name" text NOT NULL,
	"token_hash" text NOT NULL,
	"token_prefix" text NOT NULL,
	"scopes" text NOT NULL,
	"created_by" text,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp (3) with time zone,
	"last_used_at" timestamp (3) with time zone
);
--> statement-breakpoint
ALTER TABLE "service_api_tokens" ADD CONSTRAINT "service_api_tokens_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "service_api_tokens_token_hash_uidx" ON "service_api_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "service_api_tokens_tenant_idx" ON "service_api_tokens" USING btree ("tenant_id");