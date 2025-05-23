1. [클라이언트] 사용자가 로그인 버튼 클릭

─────────────────────────────────────────────
Request URI: http://127.0.0.1:8081/oauth2/authorization/springoauth2
→ Filter: OAuth2AuthorizationRequestRedirectFilter
→ 역할: 인가 요청 URI 생성 후 인가서버로 리다이렉트
→ Redirect: http://127.0.0.1:9000/oauth2/authorize?... (인가 요청)

─────────────────────────────────────────────

2. [인가 서버] 인가 요청 수신

─────────────────────────────────────────────
Request URI: http://127.0.0.1:9000/oauth2/authorize
→ Filter: OAuth2AuthorizationEndpointFilter
→ Provider: OAuth2AuthorizationCodeRequestAuthenticationProvider
→ 역할: 로그인 및 동의 처리, 인가 코드 발급
→ Redirect: http://127.0.0.1:8081/login/oauth2/code/springoauth2?code=abc123

─────────────────────────────────────────────

3. [클라이언트] 인가 코드 수신
   
─────────────────────────────────────────────

Request URI: http://127.0.0.1:8081/login/oauth2/code/springoauth2?code=abc123
→ Filter: OAuth2LoginAuthenticationFilter
→ Provider: OidcAuthorizationCodeAuthenticationProvider
→ 역할: 인가 코드로 토큰 요청 준비
→ 내부 요청: POST http://127.0.0.1:9000/oauth2/token

─────────────────────────────────────────────

4. [클라이언트 → 인가 서버] 토큰 요청
   
─────────────────────────────────────────────

Request URI: POST http://127.0.0.1:9000/oauth2/token
→ Filter: OAuth2TokenEndpointFilter
→ Provider: OAuth2AuthorizationCodeAuthenticationProvider
→ 역할: 인가 코드 검증, Access Token, Refresh Token, ID Token 발급
→ 응답: JSON(access_token, id_token 포함)

─────────────────────────────────────────────

5. [클라이언트 → 인가 서버] 공개키 요청 (OIDC 전용)
    
─────────────────────────────────────────────

Request URI: GET http://127.0.0.1:9000/oauth2/jwks
→ 처리 컴포넌트 (Spring Authorization Server 기준):
   - Controller: `JwkSetEndpointFilter` (또는 자동 등록된 JWK endpoint)
   - 내부 사용 객체: `NimbusJwkSetEndpointFilter`, `JWKSource<SecurityContext>`
→ 역할: ID Token의 서명 검증을 위한 공개키 JWKS(JSON Web Key Set) 제공
→ 사용처: `OidcAuthorizationCodeAuthenticationProvider.createOidcToken()` 내부

─────────────────────────────────────────────

6. [클라이언트] 인증 완료 처리
    
─────────────────────────────────────────────

→ Filter: OAuth2LoginAuthenticationFilter
→ authorizedClientRepository 저장
→ SecurityContextHolder 에 인증 정보 설정
→ Redirect: http://127.0.0.1:8081/

─────────────────────────────────────────────
