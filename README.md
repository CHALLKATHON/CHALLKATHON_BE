# Challkathon Demo Application

Spring Boot 기반의 인증/인가 시스템을 포함한 애플리케이션입니다.

## 기술 스택

- Kotlin
- Spring Boot 3.5.0
- Spring Security
- Spring Data JPA
- MySQL
- JWT
- OAuth2

## 데이터베이스 설정

### MySQL 설치 및 설정

1. MySQL 설치 (Mac의 경우):
```bash
brew install mysql
brew services start mysql
```

2. 데이터베이스 초기화 (스크립트 사용):
```bash
# 스크립트에 실행 권한 부여
chmod +x scripts/init-db.sh

# 스크립트 실행
./scripts/init-db.sh
```

3. 또는 수동으로 데이터베이스 생성:
```bash
mysql -u root -p
```

```sql
-- 로컬 개발용 데이터베이스
CREATE DATABASE challkathon_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 개발 서버용 데이터베이스
CREATE DATABASE challkathon_dev CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 사용자 생성 및 권한 부여 (선택사항)
CREATE USER 'challkathon'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON challkathon_db.* TO 'challkathon'@'localhost';
GRANT ALL PRIVILEGES ON challkathon_dev.* TO 'challkathon'@'localhost';
FLUSH PRIVILEGES;
```

## 환경 변수 설정

다음 환경 변수들을 설정해야 합니다:

### 데이터베이스
- `DB_USERNAME`: MySQL 사용자명 (기본값: root)
- `DB_PASSWORD`: MySQL 비밀번호

### JWT
- `JWT_SECRET`: JWT 서명에 사용할 비밀키 (최소 64자 이상)

### OAuth2 (사용하는 경우)
- `GOOGLE_CLIENT_ID`: Google OAuth2 클라이언트 ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth2 클라이언트 시크릿
- `GITHUB_CLIENT_ID`: GitHub OAuth2 클라이언트 ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth2 클라이언트 시크릿
- `NAVER_CLIENT_ID`: Naver OAuth2 클라이언트 ID
- `NAVER_CLIENT_SECRET`: Naver OAuth2 클라이언트 시크릿
- `KAKAO_CLIENT_ID`: Kakao OAuth2 클라이언트 ID
- `KAKAO_CLIENT_SECRET`: Kakao OAuth2 클라이언트 시크릿

## 실행 방법

### 로컬 개발 환경 실행
```bash
# 환경 변수 설정 후 (기본 프로파일이 local이므로 별도 지정 불필요)
./gradlew bootRun

# 또는 특정 프로파일 지정
./gradlew bootRun --args='--spring.profiles.active=local'
```

### 개발 서버 환경 실행
```bash
./gradlew bootRun --args='--spring.profiles.active=dev'
```

### 테스트 실행
```bash
./gradlew test
```

## 프로파일 설정

- `local`: 로컬 개발 환경 (MySQL 사용, DDL auto: update, 기본 프로파일)
- `dev`: 개발 서버 환경 (MySQL 사용, DDL auto: update)
- `test`: 테스트 환경 (H2 인메모리 DB 사용)

## API 문서

애플리케이션 실행 후 다음 URL에서 Swagger UI를 확인할 수 있습니다:
- http://localhost:8080/swagger-ui.html

## 주의사항

1. 첫 실행 시 데이터베이스가 비어있다면 자동으로 테이블이 생성됩니다 (ddl-auto=update).
2. JWT_SECRET은 반드시 안전한 값으로 변경해야 합니다.
3. 해커톤 데모 시에는 dev 프로파일을 사용하세요.
