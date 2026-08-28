# OIDC RP-Initiated Logout — Lodestar 구현 노트

OpenID Connect 의 [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
를 따른다. RP (Relying Party) 가 사용자를 자기 측에서 로그아웃 시킨 뒤,
Lodestar 의 `/oidc/end-session` 으로 redirect 해 IdP 측 세션도 정리하고
원래 RP 로 돌아올 수 있게 한다.

## 엔드포인트

`GET /oidc/end-session` (또는 `POST /oidc/end-session`)

| 파라미터                   | 필수   | 설명                                                                                                   |
| -------------------------- | ------ | ------------------------------------------------------------------------------------------------------ |
| `id_token_hint`            | 권장   | 로그아웃 대상의 ID Token (소유 증명). aud 검증으로 client_id 추론 가능. 있으면 확인 없이 즉시 로그아웃 |
| `client_id`                | 조건부 | `id_token_hint` 가 없으면 **필수**. 이 경로는 확인 화면을 거친다                                       |
| `post_logout_redirect_uri` | 권장   | 등록된 client.post_logout_redirect_uris 와 매칭되면 그 URI 로 302. 없거나 매칭 실패 시 `/`             |
| `state`                    | 선택   | 매칭 통과 시 post_logout_redirect_uri 에 그대로 부착                                                   |

> [!NOTE]
> `id_token_hint` 와 `client_id` 중 **적어도 하나**는 있어야 한다. 둘 다 없으면 400
> `invalid_request` 다 — RP 를 식별할 수단이 없으면 `post_logout_redirect_uri` 를 신뢰할 수 없다
> (RP-Initiated Logout §3).

## 두 갈래 흐름

규격은 `id_token_hint` 를 **RECOMMENDED** 로 두고(§2), `client_id` 를
"`post_logout_redirect_uri` 는 쓰지만 `id_token_hint` 는 쓰지 않을 때 클라이언트를 지정하는
가장 흔한 용도"로 규정한다. 그래서 Lodestar 는 두 경로를 모두 받되, **소유 증명의 유무에 따라
확인 화면을 다르게 다룬다.**

| 경로                 | 소유 증명 | 동작                                              |
| -------------------- | --------- | ------------------------------------------------- |
| `id_token_hint` 있음 | 있음      | 확인 없이 즉시 로그아웃                           |
| `client_id` 만 있음  | 없음      | **확인 화면** → 사용자가 버튼을 눌러 POST 로 확정 |

`id_token_hint` 를 세션에 보관하지 않는 RP 가 정상적으로 존재한다. ID Token 은 베어러 아티팩트라
프로세스 메모리에 오래 두지 않으려는 판단은 타당하고, 규격이 그 경우의 수단으로 `client_id` 를
제시한다. 예전에는 `id_token_hint` 를 필수로 요구해 그런 RP 의 로그아웃을 400 으로 막았다.

## 동작 흐름 — `id_token_hint` 가 있을 때

1. `id_token_hint` 가 valid 한지 검증 (signature + iss + exp)
2. `client_id` 가 주어졌으면 aud 정확 일치 검증. **누락 시 claims.aud
   첫 값을 자동 사용** (RP 가 client_id 를 빠뜨려도 redirect 가능하도록).
3. `claims.sub` 가 현재 세션 사용자와 일치하는지 검증 (sub mismatch 면 400)
4. (있다면) backchannel / frontchannel logout 통지를 RP 들에게 발송
5. 사용자 세션 폐기 (revokeSession + clearSessionCookie)
6. `post_logout_redirect_uri` 가 등록된 client 의 `post_logout_redirect_uris`
   배열의 어느 패턴과도 매칭되면 그 URI 로 302 (`state` 부착).
   아니면 `/` 로 302.

## 동작 흐름 — `client_id` 만 있을 때

1. `client_id` 가 이 테넌트에 존재하고 `enabled` 인지 확인 (아니면 400 `invalid_request`)
2. **확인 화면(200 HTML)을 렌더**한다. 폼에는 double-submit CSRF 토큰과
   `client_id` · `post_logout_redirect_uri` · `state` 가 hidden 으로 실린다.
3. 사용자가 "로그아웃" 을 누르면 같은 엔드포인트로 POST.
4. POST 는 Origin/Referer 동일 출처 검사 + **CSRF 토큰 일치**를 요구한다(불일치 403).
5. 이후는 위와 동일 — 통지 발송 → 세션 폐기 → redirect 해소.

### 왜 확인 화면인가

`id_token_hint` 가 없으면 **사용자가 로그아웃을 의도했다는 증거가 없다.** 규격 §2 가 바로 이
경우에 "OP 는 사용자에게 물어야 한다(SHOULD)"고 한다. 이 화면이 drive-by 로그아웃(CSRF)의 실질
방어선이다 — 공격자가 최상위 네비게이션으로 유도해도 버튼을 누르는 것은 사용자다.

방어는 세 겹이다.

- `Sec-Fetch-Dest != document` 인 요청은 확인 화면조차 그리지 않고 204 (`<img>`/`<iframe>` 임베드 차단)
- **미로그인 상태에서는 204** — 정리할 세션이 없는데 IdP 공식 도메인에 화면을 그려주면 phishing
  흐름의 재료가 된다(ctrls C-7)
- 폼 제출에 httpOnly 쿠키와 일치하는 CSRF 토큰 요구 — 교차 출처 공격자는 쿠키도 페이지도 읽을 수
  없어 위조할 수 없다

프레임 삽입은 전역 `X-Frame-Options: DENY` 가 막는다.

## 확인 페이지는 소유 증명이 없을 때만

confirmation 은 규격상 **SHOULD** (MUST 가 아님)다. 검증된 `id_token_hint` 는 그 자체가 소유
증명이므로 그 경로에서는 확인을 생략하고 바로 logout 처리한다 (PR #54, PR #55). 남는 drive-by
logout CSRF 표면은 단기 TTL 의 id_token 유출 + 동일 브라우저 세션 보유 상황으로 한정되며, 영향은
logout 강제뿐 (데이터 손실 없음).

`client_id` 만 온 경로는 그 증명이 없으므로 확인 화면을 거친다. 위
[동작 흐름](#동작-흐름--client_id-만-있을-때) 참고.

## RP 측 호출 예

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
- **`id_token_hint` 도 `client_id` 도 없음** → 400 `invalid_request`. RP 를 식별할 수 없으면
  `post_logout_redirect_uri` 를 신뢰할 수 없다. ID Token 을 보관하지 않는 RP 는 `client_id` 를 보내면
  된다(확인 화면을 거친다).
- **등록되지 않은 `client_id`** → 400 `invalid_request`. 비활성(`enabled=false`) 클라이언트도 같다.

## Backchannel / Frontchannel Logout

`oidc_clients` 의 `backchannel_logout_uri` / `frontchannel_logout_uri` 가
등록돼 있으면 end-session 처리 시 모든 활성 RP 에게 통지가 발송된다.

- **Backchannel**: 서버-서버 POST 로 Logout Token (JWT signed by IdP) 전송.
  RP 가 자기 측 세션을 즉시 무효화할 수 있게 함.
- **Frontchannel**: HTML 응답에 `<iframe sandbox="" referrerpolicy="no-referrer">`
  로 RP 의 frontchannel endpoint 를 로드. RP iframe 안에서 자체 세션 정리.

자세한 흐름은 `src/routes/oidc/end-session/+server.ts` 의 `executeLogout`
함수 참고.

### `sid` 계약 — ID 토큰과 같은 값이다

세션 단위 로그아웃을 쓰는 RP 에게 **`sid` 는 로그인 시 받은 ID 토큰의 `sid` 와 반드시 같은 값**이어야
한다. RP 의 구현은 보통 이렇게 생긴다.

1. 로그인 콜백에서 ID 토큰의 `sid` 를 읽어 자기 세션 레코드에 저장한다.
2. 로그아웃 통지의 `sid` 로 그 레코드를 찾아 폐기한다.

두 값이 다르면 RP 는 대상 세션을 찾지 못하고 **로그아웃이 조용히 실패**한다. 응답은 200 이고 로그에도
오류가 남지 않으므로 발견하기 어렵다.

Lodestar 가 내보내는 값은 세 곳 모두 **`sessions.id`(무작위 UUID)** 다.

| 위치                                           | 값            |
| ---------------------------------------------- | ------------- |
| ID 토큰의 `sid` 클레임                         | `sessions.id` |
| 프론트채널 로그아웃 URL 의 `sid` 쿼리 파라미터 | `sessions.id` |
| 백채널 `logout_token` 의 `sid` 클레임          | `sessions.id` |

`sessions.idp_session_id` 는 **세션 쿠키의 조회 키**(세션 토큰의 SHA-256)이므로 RP 에 내보내지 않는다.
예전에는 로그아웃 통지 쪽이 이 값을 실어 ID 토큰의 `sid` 와 어긋났는데, 그 상태에서
`backchannel_logout_session_required` 를 켜면 RP 가 매칭에 실패한다.

`*_logout_session_required` 가 **꺼져 있으면 `sid` 를 아예 보내지 않고 `sub` 만 보낸다.** 그 경우 통지의
뜻은 "이 사용자의 세션 전부"이므로, RP 는 주체 단위로 폐기해야 한다(세션 하나만 골라 끊으면 나머지가
살아남는다).

MFA step-up 으로 세션이 승격돼도 `sessions.id` 와 세션 쿠키는 유지되므로, 이미 로그인된 RP 들의 `sid`
매핑은 끊기지 않는다.

## 변경 이력

- **PR #54** (`feat/auto-logout-on-valid-hint`): GET 도 confirmation 없이
  즉시 logout 처리.
- **PR #55** (`fix/logout-redirect-without-client-id`): `client_id` 누락 시
  `id_token_hint.aud` 에서 자동 추출. RP 가 redirect 잃지 않도록.
- **2026-08-28**: 로그아웃 통지의 `sid` 를 `sessions.idp_session_id` 에서
  `sessions.id` 로 바꿔 **ID 토큰의 `sid` 와 일치**시켰다. 위
  [`sid` 계약](#sid-계약--id-토큰과-같은-값이다) 참고.
- **2026-08-29**: `id_token_hint` 필수 요구(ctrls M-10)를 풀고 `client_id` 만으로도 로그아웃할 수
  있게 했다. 규격은 `id_token_hint` 를 RECOMMENDED 로 두는데 필수로 요구해 ID Token 을 보관하지
  않는 정상적인 RP 를 400 으로 막고 있었다. 소유 증명이 없는 그 경로는 **확인 화면 + CSRF 토큰**을
  거치게 해 drive-by 로그아웃 방어를 유지한다.
