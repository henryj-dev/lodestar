# OIDC RP-Initiated Logout — Lodestar 구현 노트

OpenID Connect 의 [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
를 따른다. RP (Relying Party) 가 사용자를 자기 측에서 로그아웃 시킨 뒤,
Lodestar 의 `/oidc/end-session` 으로 redirect 해 IdP 측 세션도 정리하고
원래 RP 로 돌아올 수 있게 한다.

## 엔드포인트

`GET /oidc/end-session` (또는 `POST /oidc/end-session`)

| 파라미터                   | 필수 | 설명                                                                                       |
| -------------------------- | ---- | ------------------------------------------------------------------------------------------ |
| `id_token_hint`            | ✅   | 로그아웃 대상의 ID Token (소유 증명). aud 검증으로 client_id 추론 가능                     |
| `post_logout_redirect_uri` | 권장 | 등록된 client.post_logout_redirect_uris 와 매칭되면 그 URI 로 302. 없거나 매칭 실패 시 `/` |
| `client_id`                | 선택 | 명시되면 aud 정확 일치 검증. 누락 시 id_token_hint 의 aud 클레임에서 자동 추출             |
| `state`                    | 선택 | 매칭 통과 시 post_logout_redirect_uri 에 그대로 부착                                       |

## 동작 흐름

1. `id_token_hint` 가 valid 한지 검증 (signature + iss + exp)
2. `client_id` 가 주어졌으면 aud 정확 일치 검증. **누락 시 claims.aud
   첫 값을 자동 사용** (RP 가 client_id 를 빠뜨려도 redirect 가능하도록).
3. `claims.sub` 가 현재 세션 사용자와 일치하는지 검증 (sub mismatch 면 400)
4. (있다면) backchannel / frontchannel logout 통지를 RP 들에게 발송
5. 사용자 세션 폐기 (revokeSession + clearSessionCookie)
6. `post_logout_redirect_uri` 가 등록된 client 의 `post_logout_redirect_uris`
   배열의 어느 패턴과도 매칭되면 그 URI 로 302 (`state` 부착).
   아니면 `/` 로 302.

## 확인 페이지 미사용

OIDC Core §5 의 confirmation 은 **SHOULD** (MUST 가 아님). 검증된 `id_token_hint`
가 이미 소유 증명을 제공하므로 Lodestar 은 별도 confirm 페이지를 렌더하지
않고 바로 logout 처리한다 (PR #54, PR #55). drive-by logout CSRF 표면은
단기 TTL 의 id_token 유출 + 동일 브라우저 세션 보유 상황으로 한정되며,
영향은 logout 강제뿐 (데이터 손실 없음).

## RP 측 호출 예 (stardust dashboard)

```ts
// dashboard 의 /auth/logout 핸들러
const cfg = getOidcConfig();
const url = new URL(`${cfg.issuer}/oidc/end-session`);
url.searchParams.set("id_token_hint", session.idToken);
url.searchParams.set("post_logout_redirect_uri", `${origin}/auth/login`);
// client_id 는 명시해도 되고 생략해도 됨 (aud 에서 자동 추출)
throw redirect(302, url.toString());
```

## 자주 발생하는 실수

- **`client_id` 명시했으나 aud 와 불일치** → 400 `aud mismatch`. RP 가
  자신의 client_id 와 다른 client 의 id_token 으로 로그아웃 시도 시 발생.
- **`post_logout_redirect_uri` 가 client.post_logout_redirect_uris 에 미등록**
  → 매칭 실패 → `/` 로 302. admin UI 에서 RP 가 사용하는 모든 redirect URI
  를 등록해야 한다.
- **id_token_hint 만료** → 400 `invalid_id_token_hint`. RP 는 짧은 TTL 의
  id_token 을 세션에 저장하고 refresh 시 갱신.

## Backchannel / Frontchannel Logout

`oidc_clients` 의 `backchannel_logout_uri` / `frontchannel_logout_uri` 가
등록돼 있으면 end-session 처리 시 모든 활성 RP 에게 통지가 발송된다.

- **Backchannel**: 서버-서버 POST 로 Logout Token (JWT signed by IdP) 전송.
  RP 가 자기 측 세션을 즉시 무효화할 수 있게 함.
- **Frontchannel**: HTML 응답에 `<iframe sandbox="" referrerpolicy="no-referrer">`
  로 RP 의 frontchannel endpoint 를 로드. RP iframe 안에서 자체 세션 정리.

자세한 흐름은 `src/routes/oidc/end-session/+server.ts` 의 `executeLogout`
함수 참고.

## 변경 이력

- **PR #54** (`feat/auto-logout-on-valid-hint`): GET 도 confirmation 없이
  즉시 logout 처리.
- **PR #55** (`fix/logout-redirect-without-client-id`): `client_id` 누락 시
  `id_token_hint.aud` 에서 자동 추출. RP 가 redirect 잃지 않도록.
