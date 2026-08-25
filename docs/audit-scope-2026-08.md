# 감사 대응 범위 결정

작성일: 2026-08-25

## 배포 형태

Cloudflare Workers와 Node(adapter-node)를 지원한다. `RATELIMIT_STORE=memory|db|redis`로 저장소를 선택하며, Node 다중 레플리카는 `db` 또는 Upstash 호환 `redis`를 사용해야 전역 한도가 유지된다. Node에서 memory 저장소를 선택하면 부팅 시 운영 경고를 남긴다.

## 테넌트 라우팅

HTTP 요청은 `/t/<tenant-slug>/...` 명시 경로 또는 `IDP_TENANT_BASE_DOMAIN`이 설정된 경우 `<tenant-slug>.<base-domain>` 서브도메인으로 tenant를 식별한다. 두 값이 동시에 주어지면 불일치 요청을 거부한다. baseline cache는 tenant별로 분리되고 세션은 현재 tenant에 바인딩된다.

OIDC/SAML issuer는 `IDP_TENANT_ISSUER_MODE=shared|host|path`로 전략을 선택하며, host/path 모드에서는 tenant별 issuer를 생성한다. signing key·DB 리소스도 tenant별로 분리한다.

OIDC 웹훅은 최대 3회 즉시 재시도 후 `OIDC_WEBHOOK_QUEUE`가 있으면 Queue 메시지로 넘긴다. Queue consumer는 `deliverQueuedOidcWebhook`를 호출해야 한다.
