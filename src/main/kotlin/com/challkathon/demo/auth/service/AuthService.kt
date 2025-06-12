package com.challkathon.demo.auth.service

import AuthResponse
import com.challkathon.demo.auth.dto.request.SignInRequest
import com.challkathon.demo.auth.dto.request.SignUpRequest
import com.challkathon.demo.auth.dto.response.TokenInfoResponse
import com.challkathon.demo.auth.dto.response.UserInfoResponse
import com.challkathon.demo.auth.exception.AccountDisabledException
import com.challkathon.demo.auth.exception.EmailAlreadyExistsException
import com.challkathon.demo.auth.exception.RefreshTokenException
import com.challkathon.demo.auth.exception.code.AuthErrorStatus
import com.challkathon.demo.auth.provider.JwtProvider
import com.challkathon.demo.auth.security.UserPrincipal
import com.challkathon.demo.domain.user.entity.User
import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.challkathon.demo.domain.user.repository.UserRepository
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

private val log = KotlinLogging.logger {}

@Service
@Transactional
class AuthService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtProvider: JwtProvider,
    private val authenticationManager: AuthenticationManager,
    private val customUserDetailsService: CustomUserDetailsService,
    @Value("\${jwt.access-token-expiration:3600000}")
    private val accessTokenExpiration: Long
) {

    /**
     * 회원가입
     */
    fun signUp(signUpRequest: SignUpRequest): AuthResponse {
        log.info { "회원가입 시도: ${signUpRequest.email}" }

        // 이메일 중복 검사
        if (userRepository.existsByEmailAndAuthProvider(signUpRequest.email, AuthProvider.LOCAL)) {
            throw EmailAlreadyExistsException("이미 존재하는 이메일입니다: ${signUpRequest.email}")
        }

        // 사용자 생성
        val user = User.createLocalUser(
            email = signUpRequest.email,
            username = signUpRequest.username,
            encodedPassword = passwordEncoder.encode(signUpRequest.password)
        )

        val savedUser = userRepository.save(user)
        log.info { "새 사용자 생성 완료: ID=${savedUser.id}, Email=${savedUser.email}" }

        // UserPrincipal 생성
        val userPrincipal = UserPrincipal.create(savedUser)

        // 토큰 생성
        val accessToken = jwtProvider.generateAccessToken(userPrincipal)
        val refreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

        log.info { "회원가입 성공: ${savedUser.email}" }

        return AuthResponse(
            accessToken = accessToken,
            refreshToken = refreshToken,
            userInfo = UserInfoResponse(
                id = savedUser.id,
                email = savedUser.email,
                username = savedUser.username,
                role = savedUser.role,
                provider = savedUser.authProvider
            )
        )
    }

    /**
     * 로그인
     */
    fun signIn(signInRequest: SignInRequest): AuthResponse {
        log.info { "로그인 시도: ${signInRequest.email}" }

        try {
            // 인증
            val authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(signInRequest.email, signInRequest.password)
            )

            // UserPrincipal 가져오기
            val userPrincipal = authentication.principal as UserPrincipal

            // 토큰 생성
            val accessToken = jwtProvider.generateAccessToken(userPrincipal)
            val refreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

            // 마지막 로그인 시간 업데이트
            updateUserLastLogin(userPrincipal.email)

            log.info { "로그인 성공: ${signInRequest.email}" }

            return AuthResponse(
                accessToken = accessToken,
                refreshToken = refreshToken,
                userInfo = UserInfoResponse(
                    id = userPrincipal.id,
                    email = userPrincipal.email,
                    username = userPrincipal.userName,
                    role = userPrincipal.role,
                    provider = userPrincipal.provider
                )
            )
        } catch (e: BadCredentialsException) {
            log.warn { "로그인 실패 - 잘못된 자격 증명: ${signInRequest.email}" }
            throw BadCredentialsException("이메일 또는 비밀번호가 올바르지 않습니다")
        } catch (e: DisabledException) {
            log.warn { "로그인 실패 - 비활성화된 계정: ${signInRequest.email}" }
            throw AccountDisabledException("비활성화된 계정입니다")
        } catch (e: LockedException) {
            log.warn { "로그인 실패 - 잠긴 계정: ${signInRequest.email}" }
            throw AccountDisabledException("잠긴 계정입니다")
        } catch (e: Exception) {
            log.error(e) { "로그인 중 예상치 못한 오류: ${signInRequest.email}" }
            throw BadCredentialsException("로그인 처리 중 오류가 발생했습니다")
        }
    }

    /**
     * 토큰 갱신
     */
    fun refreshToken(refreshToken: String): AuthResponse {
        log.info { "토큰 갱신 요청" }

        try {
            // Refresh Token 유효성 검사
            if (!jwtProvider.validateRefreshToken(refreshToken)) {
                throw RefreshTokenException(AuthErrorStatus._REFRESH_TOKEN_INVALID)
            }

            val username = jwtProvider.extractUsername(refreshToken)
            log.info { "토큰 갱신 대상 사용자: $username" }

            // 최신 사용자 정보 조회
            val userPrincipal = customUserDetailsService.loadUserByUsername(username) as UserPrincipal

            // 새로운 토큰 발급
            val newAccessToken = jwtProvider.generateAccessToken(userPrincipal)
            val newRefreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

            log.info { "토큰 갱신 성공: $username" }

            return AuthResponse(
                accessToken = newAccessToken,
                refreshToken = newRefreshToken,
                userInfo = UserInfoResponse(
                    id = userPrincipal.id,
                    email = userPrincipal.email,
                    username = userPrincipal.userName,
                    role = userPrincipal.role,
                    provider = userPrincipal.provider
                )
            )
        } catch (e: RefreshTokenException) {
            log.warn { "토큰 갱신 실패: ${e.message}" }
            throw e
        } catch (e: Exception) {
            log.warn { "토큰 갱신 실패: ${e.message}" }
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
            log.warn { "토큰 검증 실패: ${e.message}" }
            false
        }
    }

    /**
     * 토큰 정보 조회
     */
    fun getTokenInfo(token: String): TokenInfoResponse? {
        return try {
            val tokenInfo = jwtProvider.getTokenInfo(token)
            tokenInfo?.let {
                TokenInfoResponse(
                    username = it.username,
                    tokenType = it.tokenType?.name ?: "UNKNOWN",
                    issuedAt = it.issuedAt.toString(),
                    expiration = it.expiration.toString(),
                    isExpired = it.isExpired,
                    remainingTimeSeconds = it.remainingTime / 1000
                )
            }
        } catch (e: Exception) {
            log.warn { "토큰 정보 조회 실패: ${e.message}" }
            null
        }
    }

    /**
     * 사용자 마지막 로그인 시간 업데이트
     */
    private fun updateUserLastLogin(email: String) {
        try {
            val user = customUserDetailsService.loadUserEntityByUsername(email)
            user.updateLastLogin()
            userRepository.save(user)
        } catch (e: Exception) {
            log.warn { "마지막 로그인 시간 업데이트 실패: $email - ${e.message}" }
            // 로그인 시간 업데이트 실패는 전체 로그인 프로세스를 중단시키지 않음
        }
    }
}