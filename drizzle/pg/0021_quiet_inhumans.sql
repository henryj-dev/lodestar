ALTER TABLE "oidc_clients" ADD COLUMN "require_mfa" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "oidc_clients" ADD COLUMN "reauth_policy" text DEFAULT 'full' NOT NULL;--> statement-breakpoint
ALTER TABLE "saml_sps" ADD COLUMN "require_mfa" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "saml_sps" ADD COLUMN "reauth_policy" text DEFAULT 'full' NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "auth_time" timestamp (3) with time zone;