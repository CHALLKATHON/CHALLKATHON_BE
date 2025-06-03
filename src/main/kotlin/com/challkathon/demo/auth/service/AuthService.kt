package com.example.auth.service

import com.challkathon.demo.auth.excepetion.EmailAlreadyExistsException
import com.challkathon.demo.auth.provider.JwtProvider
import com.challkathon.demo.auth.service.CustomUserDetailsService
import com.challkathon.demo.domain.user.entity.User
import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.challkathon.demo.domain.user.repository.UserRepository
import com.example.auth.security.UserPrincipal
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional
class AuthService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtProvider: JwtProvider,
    private val authenticationManager: AuthenticationManager,
    private val userDetailsService: CustomUserDetailsService
) {

    private val logger = LoggerFactory.getLogger(AuthService::class.java)

    fun signUp(signUpRequest: SignUpRequest): AuthResponse {
        logger.info("회원가입 시도: {}", signUpRequest.email)

        // UserDetailsService를 통한 중복 검사
        if (userDetailsService.existsByEmail(signUpRequest.email)) {
            throw EmailAlreadyExistsException("이미 존재하는 이메일입니다: ${signUpRequest.email}")
        }

        // 사용자 생성
        val user = User(
            email = signUpRequest.email,
            password = passwordEncoder.encode(signUpRequest.password),
            username = signUpRequest.name,
            authProvider = AuthProvider.LOCAL
        )

        val savedUser = userRepository.save(user)
        logger.info("새 사용자 생성 완료: ID={}, Email={}", savedUser.id, savedUser.email)

        // UserDetailsService를 통해 UserPrincipal 획득
        val userPrincipal = userDetailsService.loadUserByUsername(savedUser.email) as UserPrincipal

        // 토큰 생성
        val accessToken = jwtProvider.generateAccessToken(userPrincipal)
        val refreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

        logger.info("회원가입 성공: {}", savedUser.email)

        return AuthResponse(
            accessToken = accessToken,
            refreshToken = refreshToken,
            user = UserInfo(
                id = userPrincipal.id,
                email = userPrincipal.email,
                name = userPrincipal.name,
                role = userPrincipal.role,
                provider = userPrincipal.provider
            )
        )
    }

    fun signIn(signInRequest: SignInRequest): AuthResponse {
        logger.info("로그인 시도: {}", signInRequest.email)

        try {
            // 인증 (UserDetailsService가 자동으로 UserPrincipal 반환)
            val authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(signInRequest.email, signInRequest.password)
            )

            // authentication.principal은 UserDetailsService가 반환한 UserPrincipal
            val userPrincipal = authentication.principal as UserPrincipal

            // 토큰 생성
            val accessToken = jwtProvider.generateAccessToken(userPrincipal)
            val refreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

            // 마지막 로그인 시간 업데이트
            updateUserLastLogin(userPrincipal.email)

            logger.info("로그인 성공: {}", signInRequest.email)

            return AuthResponse(
                accessToken = accessToken,
                refreshToken = refreshToken,
                user = UserInfo(
                    id = userPrincipal.id,
                    email = userPrincipal.email,
                    name = userPrincipal.name,
                    role = userPrincipal.role,
                    provider = userPrincipal.provider
                )
            )
        } catch (e: Exception) {
            logger.warn("로그인 실패: {} - {}", signInRequest.email, e.message)
            throw e
        }
    }

    fun refreshToken(refreshTokenRequest: RefreshTokenRequest): AuthResponse {
        val refreshToken = refreshTokenRequest.refreshToken

        logger.info("토큰 갱신 요청")

        try {
            // Refresh Token 유효성 검사
            if (!jwtProvider.validateRefreshToken(refreshToken)) {
                throw RefreshTokenException(AuthErrorStatus._REFRESH_TOKEN_INVALID)
            }

            val username = jwtProvider.extractUsername(refreshToken)
            logger.info("토큰 갱신 대상 사용자: {}", username)

            // UserDetailsService를 통해 최신 사용자 정보 조회
            val userPrincipal = userDetailsService.loadUserByUsername(username) as UserPrincipal

            // 새로운 토큰 발급
            val newAccessToken = jwtProvider.generateAccessToken(userPrincipal)
            val newRefreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

            logger.info("토큰 갱신 성공: {}", username)

            return AuthResponse(
                accessToken = newAccessToken,
                refreshToken = newRefreshToken,
                user = UserInfo(
                    id = userPrincipal.id,
                    email = userPrincipal.email,
                    name = userPrincipal.name,
                    role = userPrincipal.role,
                    provider = userPrincipal.provider
                )
            )
        } catch (e: RefreshTokenException) {
            logger.warn("토큰 갱신 실패: {}", e.message)
            throw e
        } catch (e: Exception) {
            logger.warn("토큰 갱신 실패: {}", e.message)
            throw RefreshTokenException(AuthErrorStatus._REFRESH_TOKEN_INVALID)
        }
    }

    /**
     * 토큰 검증
     */
    fun validateToken(token: String): Boolean {
        return try {
            jwtProvider.validateAccessToken(token)
        } catch (e: Exception) {
            logger.warn("토큰 검증 실패: {}", e.message)
            false
        }
    }

    /**
     * 토큰 정보 조회
     */
    fun getTokenInfo(token: String): Map<String, Any>? {
        return try {
            val tokenInfo = jwtProvider.getTokenInfo(token)
            tokenInfo?.let {
                mapOf(
                    "username" to it.username,
                    "tokenType" to (it.tokenType?.name ?: "UNKNOWN"),
                    "issuedAt" to it.issuedAt,
                    "expiration" to it.expiration,
                    "isExpired" to it.isExpired,
                    "remainingTimeSeconds" to (it.remainingTime / 1000)
                )
            }
        } catch (e: Exception) {
            logger.warn("토큰 정보 조회 실패: {}", e.message)
            null
        }
    }

    /**
     * OAuth2 사용자 등록 또는 업데이트
     */
    fun processOAuthPostLogin(email: String, name: String, provider: AuthProvider, providerId: String): User {
        logger.info("OAuth2 로그인 처리: {} ({})", email, provider)

        val existingUser = userRepository.findByEmailAndProvider(email, provider)

        return if (existingUser.isPresent) {
            // 기존 사용자 업데이트
            val user = existingUser.get()
            user.updateLastLogin()
            val updatedUser = userRepository.save(user)
            logger.info("기존 OAuth2 사용자 로그인: {}", email)
            updatedUser
        } else {
            // 새 사용자 생성
            val newUser = User(
                email = email,
                name = name,
                provider = provider,
                providerId = providerId
            )
            val savedUser = userRepository.save(newUser)
            logger.info("새 OAuth2 사용자 생성: {}", email)
            savedUser
        }
    }

    /**
     * 사용자 마지막 로그인 시간 업데이트
     */
    private fun updateUserLastLogin(email: String) {
        try {
            val user = userDetailsService.loadUserEntityByUsername(email)
            user.updateLastLogin()
            userRepository.save(user)
        } catch (e: Exception) {
            logger.warn("마지막 로그인 시간 업데이트 실패: {} - {}", email, e.message)
            // 로그인 시간 업데이트 실패는 전체 로그인 프로세스를 중단시키지 않음
        }
    }
}