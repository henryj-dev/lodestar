# stardust back-channel logout 운영 E2E 확인 요청

작성일: 2026-08-25  
발신: tiny-universe/stardust  
수신: mack-erel/KeyStone 운영·개발 담당자

## 요약

stardust에 전용 실제 IdP 계정 `e2e-test`를 만들고 운영 dashboard에서 로그인·로그아웃을 실행했다.
로그인 시 stardust dispatcher DB에 OIDC `sid` 바인딩은 생성됐지만, 로그아웃 직후 해당 `sid`에 대한
`session_revocations` 기록은 생성되지 않았다.

따라서 dashboard의 로컬 로그아웃은 성공했지만, KeyStone에서 stardust의 back-channel logout endpoint로
유효한 Logout Token이 도착해 세션 폐기를 완료했다는 증거는 아직 없다.

## 관측 결과

| 단계 | 결과 |
|---|---|
| 실제 IdP 계정 | `e2e-test` 활성 계정 확인 |
| stardust 로그인 | 성공. dashboard 상단에 `e2e-test@` 표시 |
| 로그인 후 DB | `session_bindings`에 sid·idp_sub 바인딩 생성 |
| dashboard 로그아웃 | 성공. IdP 로그인 화면으로 리다이렉트 |
| 로그아웃 후 DB | 해당 sid의 `session_revocations.revoked_at`는 `NULL` |
| 전체 판정 | 로컬 로그아웃 성공, back-channel 착지는 미확인·실패 가능성 있음 |

비밀번호, 토큰, sid 원문과 같은 민감한 값은 기록하지 않았다.

## 현재 등록값

stardust OIDC client에 대해 운영 DB read-only 확인으로 다음을 확인했다.

- `backchannel_logout_uri`: `https://stardust.tinyuniverse.se/auth/backchannel-logout`
- `backchannel_logout_session_required`: `false`

`session_required=false` 자체는 오류가 아니다. 이 모드에서도 KeyStone은 `sub`가 포함된 Logout Token을
발송해야 하며, stardust는 `sub` 또는 `sid`를 받아 처리하도록 구현되어 있다. 따라서 우선 이 값을
`true`로 바꾸기보다 실제 발송 대상과 발송 결과를 확인해야 한다.

## KeyStone에서 확인할 항목

다음 항목을 운영 DB 또는 안전한 진단 로그로 확인해 달라.

1. 해당 OIDC client가 현재 tenant에서 `enabled=true`인지
2. `backchannel_logout_uri`가 위 endpoint와 정확히 일치하는지
3. `e2e-test`의 현재 로그인 세션에 stardust client의 OIDC grant 또는 refresh token이 연결되어 있는지
4. RP-initiated logout(`/oidc/end-session`) 처리 중 stardust client가 back-channel target으로 선택됐는지
5. Logout Token POST가 실제로 시도됐는지
6. 시도됐다면 응답 상태 코드와 네트워크/DNS/SSRF 허용 검사에서 거절되지 않았는지
7. `signingKeySecrets`와 활성 signing key가 존재해 Logout Token 서명이 가능했는지

특히 현재 KeyStone 구현의 세션 단위 target 조회는 해당 IdP 세션에 연결된 grant 또는 refresh token이
있는 client만 대상으로 삼는 구조이므로, client 등록값만 존재하고 세션 연결이 없으면 발송 대상에서
빠질 수 있다.

## 권고 순서

1. 먼저 client 등록·tenant·세션 grant 연결과 발송 결과를 read-only로 확인한다.
2. 발송 대상이 없으면 OIDC grant/session 연결 로직을 원인으로 분리한다.
3. 발송 대상은 있으나 네트워크 호출이 실패하면 endpoint 도달성, URL 허용 정책, DNS 해석을 확인한다.
4. 발송과 응답이 모두 정상인데 stardust DB에 revocation이 없으면 Logout Token의 claims(`iss`, `aud`, `sub`,
   `iat`, `jti`, `events`)와 dashboard 응답을 상관 분석한다. 토큰 원문은 남기지 않는다.
5. 위 확인이 끝난 뒤에만 `backchannel_logout_session_required=true` 변경 여부를 별도로 결정한다.

## stardust 측 완료 조건

다음 증거가 모이면 C-07을 완료로 판정할 수 있다.

- 실제 KeyStone Logout Token이 stardust endpoint에 도달
- 해당 `sid`의 `session_revocations.revoked_at` 생성
- 같은 token 재전송 시 duplicate 처리
- 다른 subject와 sid를 섞은 요청이 거절됨
- 실패 요청이 `oidc_logout_failures`에 영속 기록됨

현재는 마지막 항목과 인증 누락 401 감사 기록은 확인했지만, 실제 유효 Logout Token을 통한 앞의 세
항목은 아직 확인하지 못했다.
