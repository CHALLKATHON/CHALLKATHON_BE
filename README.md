# Spring Security + JWT + OAuth2 인증 시스템 (Kotlin)

이 프로젝트는 Spring Security, JWT, OAuth2를 사용하여 일반 로그인/회원가입과 소셜 로그인을 지원하는 엔터프라이즈급 인증 시스템입니다.

## 🚀 주요 기능

- ✅ **일반 회원가입/로그인** (이메일 + 비밀번호)
- ✅ **JWT 기반 인증** (Access Token + Refresh Token)
- ✅ **OAuth2 소셜 로그인** (Kakao, Naver)
- ✅ **사용자 권한 관리** (USER, ADMIN)
- ✅ **토큰 관리 API** (검증, 정보 조회, 갱신)
- ✅ **예외 처리** (체계적인 에러 응답)
- ✅ **로깅 및 모니터링**
- ✅ **캐시 지원** (성능 최적화)

## 🏗️ 아키텍처 특징

### 관심사 분리 (Separation of Concerns)

- **User 엔티티**: 순수 도메인 객체 (비즈니스 로직만)
- **UserPrincipal**: Spring Security 전용 래퍼 클래스
- **JwtProvider**: JWT 토큰 생성/검증 전담
- **UserDetailsService**: 사용자 조회 및 변환 중앙집중

### JWT 토큰 설계

- **Access Token**: 짧은 수명 (1시간), API 접근용
- **Refresh Token**: 긴 수명 (7일), 토큰 갱신용
- **토큰 타입 구분**: ACCESS/REFRESH 명시적 분리
- **상세한 토큰 정보**: 권한, 발행시간, 만료시간 등 포함

## 📋 요구사항

- Java 17+
- Kotlin 1.9.20+
- Spring Boot 3.2.0+

## 🛠 설정 방법

### 1. OAuth2 클라이언트 설정

#### Kakao OAuth2

1. [카카오 개발자 센터](https://developers.kakao.com/) 방문
2. "내 애플리케이션" > "애플리케이션 추가하기"
3. "플랫폼" > "Web" 추가
4. "사이트 도메인": `http://localhost:8080`
5. "카카오 로그인" > "Redirect URI": `http://localhost:8080/oauth2/callback/kakao`
6. "동의항목" > "닉네임", "카카오계정(이메일)" 필수 선택

#### Naver OAuth2

1. [네이버 개발자 센터](https://developers.naver.com/) 방문
2. "애플리케이션 등록" 진행
3. 서비스 URL: `http://localhost:8080`
4. Callback URL: `http://localhost:8080/oauth2/callback/naver`

### 2. 환경 변수 설정

```bash
# JWT 설정
export JWT_SECRET="your-strong-jwt-secret-key-at-least-256-bits"
export JWT_ISSUER="your-app-name"

# OAuth2 클라이언트 ID/Secret
export KAKAO_CLIENT_ID="your-kakao-client-id"
export KAKAO_CLIENT_SECRET="your-kakao-client-secret"
export NAVER_CLIENT_ID="your-naver-client-id"
export NAVER_CLIENT_SECRET="your-naver-client-secret"

# 허용된 리디렉션 URI
export AUTHORIZED_REDIRECT_URIS="http://localhost:3000/oauth2/redirect,https://yourdomain.com/oauth2/redirect"
```

### 3. 데이터베이스 설정 (운영환경)

```bash
export DATABASE_URL="jdbc:mysql://localhost:3306/authdb"
export DATABASE_USERNAME="your-db-username"
export DATABASE_PASSWORD="your-db-password"
```

## 🔧 실행 방법

```bash
# 개발 환경으로 실행
./gradlew bootRun

# 또는 JAR 파일 빌드 후 실행
./gradlew build
java -jar build/libs/auth-app-0.0.1-SNAPSHOT.jar
```

## 📡 API 엔드포인트

### 인증 API

#### 회원가입

```http
POST /api/auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "name": "홍길동"
}
```

**응답**

```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "eyJhbGciOiJIUzUxMiJ9...",
  "tokenType": "Bearer",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "name": "홍길동",
    "role": "USER",
    "provider": "LOCAL"
  }
}
```

#### 로그인

```http
POST /api/auth/signin
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### 토큰 갱신

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### 현재 사용자 정보

```http
GET /api/auth/me
Authorization: Bearer your-access-token
```

#### 인증 상태 확인

```http
GET /api/auth/status
Authorization: Bearer your-access-token
```

### JWT 관리 API

#### 토큰 검증

```http
POST /api/jwt/validate
Content-Type: application/json

{
  "token": "your-access-token"
}
```

#### 토큰 정보 조회

```http
POST /api/jwt/info
Content-Type: application/json

{
  "token": "your-access-token"
}
```

#### Bearer 토큰 정보 조회

```http
GET /api/jwt/info
Authorization: Bearer your-access-token
```

**응답**

```json
{
  "success": true,
  "data": {
    "username": "user@example.com",
    "tokenType": "ACCESS",
    "issuedAt": "2024-01-01T10:00:00",
    "expiration": "2024-01-01T11:00:00",
    "isExpired": false,
    "remainingTimeSeconds": 3540
  }
}
```

### OAuth2 로그인 URL

- **Kakao**: `http://localhost:8080/oauth2/authorize/kakao?redirect_uri=http://localhost:3000/oauth2/redirect`
- **Naver**: `http://localhost:8080/oauth2/authorize/naver?redirect_uri=http://localhost:3000/oauth2/redirect`

### 테스트 API

```http
# 공개 엔드포인트
GET /api/test/public

# 인증 필요 엔드포인트
GET /api/test/user
Authorization: Bearer your-access-token

# 관리자 전용 엔드포인트
GET /api/test/admin
Authorization: Bearer your-access-token
```

## 🔒 보안 특징

### JWT 토큰

- **Access Token**: 1시간 유효, API 접근용
- **Refresh Token**: 7일 유효, 토큰 갱신용
- **HS512 알고리즘** 사용
- **토큰 타입 구분**: ACCESS/REFRESH 명시
- **상세 메타데이터**: 권한, 발행시간, 만료시간 포함

### 보안 헤더 및 설정

- **CORS** 설정으로 도메인 간 요청 제어
- **CSRF** 비활성화 (JWT 사용으로 불필요)
- **Session** 비활성화 (Stateless 아키텍처)
- **BCrypt** 비밀번호 암호화

### 예외 처리

- **체계적인 에러 응답** (ErrorResponse DTO)
- **구체적인 예외 타입** (JwtAuthenticationException, EmailAlreadyExistsException 등)
- **보안 정보 노출 방지**

## 🗂 프로젝트 구조

```
src/main/kotlin/com/example/auth/
├── config/
│   ├── SecurityConfig.kt              # Spring Security 설정
│   └── CacheConfig.kt                 # 캐시 설정
├── controller/
│   ├── AuthController.kt              # 인증 API 컨트롤러
│   ├── JwtController.kt               # JWT 관리 컨트롤러
│   └── TestController.kt              # 테스트 API 컨트롤러
├── entity/
│   └── User.kt                        # 사용자 엔티티 및 DTO
├── exception/
│   └── AuthExceptionHandler.kt        # 전역 예외 처리
├── filter/
│   └── JwtAuthenticationFilter.kt     # JWT 인증 필터
├── handler/
│   └── OAuth2AuthenticationSuccessHandler.kt  # OAuth2 성공 핸들러
├── provider/
│   └── JwtProvider.kt                 # JWT 토큰 제공자
├── repository/
│   └── UserRepository.kt              # 사용자 Repository
├── security/
│   └── UserPrincipal.kt               # Security 래퍼 클래스
├── service/
│   ├── AuthService.kt                 # 인증 서비스
│   ├── CustomOAuth2UserService.kt     # OAuth2 사용자 서비스
│   └── CustomUserDetailsService.kt    # UserDetails 서비스
└── AuthApplication.kt                 # 메인 애플리케이션
```

## 🧪 테스트 방법

### 1. 일반 회원가입/로그인 테스트

```bash
# 회원가입
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "name": "테스트 사용자"
  }'

# 로그인
curl -X POST http://localhost:8080/api/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

### 2. JWT 토큰 테스트

```bash
# 토큰 검증
curl -X POST http://localhost:8080/api/jwt/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_ACCESS_TOKEN"}'

# 토큰 정보 조회
curl -X GET http://localhost:8080/api/jwt/info \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# 사용자 정보 조회
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 3. OAuth2 로그인 테스트

브라우저에서 다음 URL 방문:

```
http://localhost:8080/oauth2/authorize/kakao?redirect_uri=http://localhost:3000/oauth2/redirect
```

## ⚡ 성능 최적화

### 캐싱

- **UserDetails 캐싱**: 사용자 조회 성능 향상
- **User 엔티티 캐싱**: 데이터베이스 부하 감소
- **설정 가능한 캐시**: ConcurrentMapCacheManager (개발), Redis (운영)

### 로깅

- **구조화된 로깅**: 인증 이벤트 추적
- **성능 모니터링**: 토큰 생성/검증 시간 측정
- **보안 이벤트**: 실패한 로그인 시도 기록

## 🚨 보안 고려사항

### JWT 보안

1. **강력한 시크릿 키**: 최소 256비트 이상
2. **토큰 만료 시간**: Access Token은 짧게, Refresh Token은 적절히
3. **토큰 갱신 정책**: Refresh Token 재사용 방지

### 일반 보안

1. **HTTPS 필수**: 운영환경에서 반드시 사용
2. **환경변수 관리**: 민감한 정보는 환경변수로 관리
3. **입력 검증**: 모든 사용자 입력 검증
4. **에러 메시지**: 보안 정보 노출 방지

## 🔄 리팩토링 히스토리

### 주요 개선사항

1. **JwtUtil → JwtProvider**: 더 명확한 네이밍과 역할 정의
2. **User 엔티티 분리**: UserDetails 구현 제거로 관심사 분리
3. **UserPrincipal 래퍼**: Spring Security 전용 클래스 도입
4. **중앙화된 변환 로직**: UserDetailsService에서 User → UserPrincipal 변환
5. **체계적인 예외 처리**: 구체적인 예외 타입과 처리 로직

## 📝 추가 개발 사항

- [ ] **이메일 인증** 기능
- [ ] **비밀번호 재설정** 기능
- [ ] **사용자 프로필 관리**
- [ ] **로그인 시도 제한** (Rate Limiting)
- [ ] **Redis 기반 토큰 관리**
- [ ] **소셜 로그인 계정 연동**
- [ ] **감사 로그** (Audit Log)
- [ ] **메트릭스 수집** (Micrometer)

## 🤝 기여 방법

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 라이센스

이 프로젝트는 MIT 라이센스 하에 있습니다. 자세한 내용은 LICENSE 파일을 참조하세요.

---

**💡 Tip**: 이 프로젝트는 엔터프라이즈급 Spring Security 아키텍처의 베스트 프랙티스를 구현했습니다. 프로덕션 환경에서 사용하기 전에 보안 검토를 진행하세요!