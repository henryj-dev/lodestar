import { error } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { getRuntimeConfig, resolveIssuerUrl } from "$lib/server/auth/runtime";
import { generateIdpMetadataXml } from "$lib/server/saml/metadata";
import { findSp } from "$lib/server/saml/sp";
import { translate } from "$lib/i18n/server";

export const GET: RequestHandler = async ({ locals, platform, url }) => {
    const { db, tenant } = requireDbContext(locals);
    const config = getRuntimeConfig(platform);

    if (!config.issuerUrl) {
        throw error(503, translate(locals.locale, "saml.errors.issuer_not_set"));
    }

    // SP 컨텍스트가 주어지면(`?sp=<entityId>`) 해당 SP의 wantAuthnRequestsSigned 를 광고에 반영.
    // 없으면 IdP 전역 metadata 로 기본(false) 동작 유지.
    const spEntityId = url.searchParams.get("sp");
    const sp = spEntityId ? await findSp(db, tenant.id, spEntityId) : null;

    const issuer = resolveIssuerUrl(config, url.origin, tenant.slug);
    const xml = await generateIdpMetadataXml(db, tenant.id, issuer, sp?.wantAuthnRequestsSigned ?? false);

    return new Response(xml, {
        headers: {
            "Content-Type": "application/samlmetadata+xml; charset=utf-8",
            "Cache-Control": "public, max-age=3600",
            // 테넌트/SP 별 응답이 공유 캐시에서 섞이지 않도록 캐시 키를 분리한다.
            Vary: "Accept, Host",
        },
    });
};
