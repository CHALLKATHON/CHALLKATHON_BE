# Spring Security + OAuth2 인증 시스템

Spring Boot 3.x, Kotlin, Spring Security를 사용한 JWT 기반 인증 시스템입니다.

## 🚀 주요 기능

- **일반 로그인/회원가입**: 이메일과 비밀번호를 사용한 인증
- **소셜 로그인**: Google, GitHub, Kakao, Naver OAuth2 지원
- **JWT 토큰 인증**: Access Token과 Refresh Token을 사용한 stateless 인증
- **권한 관리**: USER, ADMIN 역할 기반 접근 제어
- **Swagger UI**: API 문서 자동 생성

## 🛠 기술 스택

- **Backend**: Spring Boot 3.5.0, Kotlin 1.9.25
- **Security**: Spring Security, OAuth2 Client
- **Database**: MySQL (운영), H2 (개발)
- **ORM**: Spring Data JPA, Hibernate
- **인증**: JWT (jjwt 0.12.3)
- **API 문서**: SpringDoc OpenAPI 2.2.0
- **로깅**: Kotlin Logging

## 📁 프로젝트 구조

```
src/main/kotlin/com/challkathon/demo/
├── auth/                      # 인증 관련 모듈
│   ├── controller/           # 인증 API 컨트롤러
│   ├── dto/                  # 요청/응답 DTO
│   ├── enums/                # 토큰 타입 enum
│   ├── exception/            # 인증 관련 예외
│   ├── filter/               # JWT 인증 필터
│   ├── handler/              # OAuth2 성공/실패 핸들러
│   ├── provider/             # JWT 토큰 제공자
│   ├── security/             # UserPrincipal
│   ├── service/              # 인증 서비스
│   └── util/                 # 토큰 쿠키 유틸
├── domain/                    # 도메인 모델
│   └── user/
│       ├── entity/           # User 엔티티
│       └── repository/       # User 리포지토리
├── global/                    # 전역 설정
│   ├── common/               # 공통 클래스
│   ├── config/               # Security, JPA, Swagger 설정
│   └── exception/            # 전역 예외 처리
└── test/                      # 테스트 컨트롤러
```

## 🔧 설정

### 환경 변수

```yaml
# 데이터베이스
DB_USERNAME: 데이터베이스 사용자명
DB_PASSWORD: 데이터베이스 비밀번호

# JWT
JWT_SECRET: JWT 시크릿 키 (최소 64자)
JWT_ACCESS_TOKEN_EXPIRATION: 액세스 토큰 만료 시간 (밀리초)
JWT_REFRESH_TOKEN_EXPIRATION: 리프레시 토큰 만료 시간 (밀리초)

# OAuth2
GOOGLE_CLIENT_ID: Google OAuth2 클라이언트 ID
GOOGLE_CLIENT_SECRET: Google OAuth2 클라이언트 시크릿
GITHUB_CLIENT_ID: GitHub OAuth2 클라이언트 ID
GITHUB_CLIENT_SECRET: GitHub OAuth2 클라이언트 시크릿
KAKAO_CLIENT_ID: Kakao OAuth2 클라이언트 ID
KAKAO_CLIENT_SECRET: Kakao OAuth2 클라이언트 시크릿
NAVER_CLIENT_ID: Naver OAuth2 클라이언트 ID
NAVER_CLIENT_SECRET: Naver OAuth2 클라이언트 시크릿
```

## 🚀 실행 방법

### 개발 환경

```bash
# 프로젝트 클론
git clone https://github.com/challkathon/demo.git
cd demo

# 개발 환경으로 실행 (H2 데이터베이스 사용)
./gradlew bootRun --args='--spring.profiles.active=dev'
```

### 운영 환경

```bash
# MySQL 데이터베이스 준비
# application.yml의 datasource 설정 확인

# 운영 환경으로 실행
./gradlew bootRun --args='--spring.profiles.active=prod'
```

## 📚 API 문서

애플리케이션 실행 후 Swagger UI를 통해 API 문서를 확인할 수 있습니다:
- http://localhost:8080/swagger-ui.html

## 🔑 API 엔드포인트

### 인증 API

| 메서드 | 경로 | 설명 | 인증 필요 |
|--------|------|------|-----------|
| POST | `/api/v1/auth/signup` | 회원가입 | ❌ |
| POST | `/api/v1/auth/signin` | 로그인 | ❌ |
| POST | `/api/v1/auth/refresh` | 토큰 갱신 | ❌ |
| POST | `/api/v1/auth/logout` | 로그아웃 | ✅ |
| GET | `/api/v1/auth/token-info` | 토큰 상세 정보 조회 | ✅ |
| GET | `/api/v1/auth/me` | 현재 사용자 정보 | ✅ |

### OAuth2 엔드포인트

| Provider | 인증 URL |
|----------|----------|
| Google | `/oauth2/authorize/google` |
| GitHub | `/oauth2/authorize/github` |
| Kakao | `/oauth2/authorize/kakao` |
| Naver | `/oauth2/authorize/naver` |

### 테스트 API

| 메서드 | 경로 | 설명 | 필요 권한 |
|--------|------|------|-----------|
| GET | `/api/v1/test/public` | 공개 API | 없음 |
| GET | `/api/v1/test/authenticated` | 인증 필요 | 로그인 |
| GET | `/api/v1/test/user` | USER 권한 필요 | USER |
| GET | `/api/v1/test/admin` | ADMIN 권한 필요 | ADMIN |

## 🔒 보안 설정 및 주의사항

### JWT 시크릿 키 설정 (필수!)
```bash
# 환경변수 설정 예시 (.env 파일)
export JWT_SECRET=$(openssl rand -base64 64)
# 또는
export JWT_SECRET="your-very-long-random-secret-key-at-least-64-characters-for-security"
```

> ⚠️ **경고**: 기본 JWT 시크릿 키를 그대로 사용하지 마세요! 반드시 보안이 강한 랜덤 키로 변경하세요.

### CORS 설정
```yaml
# 프로덕션 환경에서는 특정 origin만 허용
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

## 🔒 보안 설정

- CORS 설정: 개발 환경에서만 localhost 허용, 운영 환경에서는 특정 도메인만 허용
- JWT 토큰: Bearer 방식으로 Authorization 헤더에 전송
- 비밀번호: BCrypt 암호화
- OAuth2: 인증 후 JWT 토큰 발급
- 예외 처리: 모든 인증 오류에 대한 표준화된 응답

## 📝 사용 예시

### 회원가입
```bash
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "username": "testuser"
  }'
```

### 로그인
```bash
curl -X POST http://localhost:8080/api/v1/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

### 인증된 API 호출
```bash
curl -X GET http://localhost:8080/api/v1/test/authenticated \
  -H "Authorization: Bearer {access_token}"
```

## 🧪 개발 도구

### H2 Console (개발 환경)
- URL: http://localhost:8080/h2-console
- JDBC URL: `jdbc:h2:mem:devdb`
- Username: `sa`
- Password: (비어있음)

## 📄 라이센스

이 프로젝트는 Apache 2.0 라이센스를 따릅니다.