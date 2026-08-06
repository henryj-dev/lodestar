CREATE TABLE "oidc_client_sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"session_id" text NOT NULL,
	"client_id" text NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "oidc_client_sessions" ADD CONSTRAINT "oidc_client_sessions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oidc_client_sessions" ADD CONSTRAINT "oidc_client_sessions_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "oidc_client_sessions_session_client_uidx" ON "oidc_client_sessions" USING btree ("session_id","client_id");--> statement-breakpoint
CREATE INDEX "oidc_client_sessions_tenant_session_idx" ON "oidc_client_sessions" USING btree ("tenant_id","session_id");