package com.challkathon.demo.auth.provider

import TokenType
import com.challkathon.demo.auth.excepetion.code.AuthErrorStatus
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtProvider {

    private val logger = LoggerFactory.getLogger(JwtProvider::class.java)

    @Value("\${jwt.secret:mySecretKey12345678901234567890123456789012345678901234567890}")
    private lateinit var secret: String

    @Value("\${jwt.access-token.expiration:3600000}") // 1시간
    private var accessTokenExpiration: Long = 3600000

    @Value("\${jwt.refresh-token.expiration:604800000}") // 7일
    private var refreshTokenExpiration: Long = 604800000

    @Value("\${jwt.issuer:spring-auth-app}")
    private lateinit var issuer: String

    private val key: SecretKey by lazy {
        Keys.hmacShaKeyFor(secret.toByteArray())
    }

    // ========== 토큰 생성 메서드들 ==========

    /**
     * Access Token 생성
     */
    fun generateAccessToken(userDetails: UserDetails): String {
        return generateToken(
            subject = userDetails.username,
            expiration = accessTokenExpiration,
            tokenType = TokenType.ACCESS,
            additionalClaims = mapOf(
                "authorities" to userDetails.authorities.map { it.authority }
            )
        )
    }

    /**
     * Refresh Token 생성
     */
    fun generateRefreshToken(username: String): String {
        return generateToken(
            subject = username,
            expiration = refreshTokenExpiration,
            tokenType = TokenType.REFRESH
        )
    }

    /**
     * 토큰 생성 (내부 메서드)
     */
    private fun generateToken(
        subject: String,
        expiration: Long,
        tokenType: TokenType,
        additionalClaims: Map<String, Any> = emptyMap()
    ): String {
        val now = Date()
        val expiryDate = Date(now.time + expiration)

        return Jwts.builder()
            .subject(subject)
            .issuer(issuer)
            .issuedAt(now)
            .expiration(expiryDate)
            .claim("type", tokenType.name)
            .claims(additionalClaims)
            .signWith(key) // 0.12.x에서는 알고리즘 자동 감지
            .compact()
    }

    // ========== 토큰 추출 메서드들 ==========

    /**
     * 토큰에서 사용자명 추출
     */
    fun extractUsername(token: String): String {
        return extractClaim(token, Claims::getSubject)
    }

    /**
     * 토큰에서 사용자 ID 추출 (추가 기능)
     */
    fun extractUserId(token: String): Long? {
        return try {
            val userIdClaim = extractClaim(token) { claims: Claims ->
                claims["userId"]
            }
            userIdClaim?.toString()?.toLong()
        } catch (e: Exception) {
            logger.warn("토큰에서 사용자 ID를 추출할 수 없습니다", e)
            null
        }
    }

    /**
     * 토큰에서 권한 정보 추출
     */
    fun extractAuthorities(token: String): List<String> {
        return try {
            extractClaim(token) { claims: Claims ->
                @Suppress("UNCHECKED_CAST")
                claims["authorities"] as? List<String> ?: emptyList()
            }
        } catch (e: Exception) {
            logger.warn("토큰에서 권한 정보를 추출할 수 없습니다", e)
            emptyList()
        }
    }

    /**
     * 토큰에서 만료 시간 추출
     */
    fun extractExpiration(token: String): Date {
        return extractClaim(token, Claims::getExpiration)
    }

    /**
     * 토큰에서 발행 시간 추출
     */
    fun extractIssuedAt(token: String): Date {
        return extractClaim(token, Claims::getIssuedAt)
    }

    /**
     * 토큰 타입 추출
     */
    fun extractTokenType(token: String): TokenType? {
        return try {
            val type = extractClaim(token) { claims: Claims ->
                claims["type"] as? String
            }
            type?.let { TokenType.valueOf(it) }
        } catch (e: Exception) {
            logger.warn("토큰 타입을 추출할 수 없습니다", e)
            null
        }
    }

    /**
     * 토큰에서 특정 클레임 추출
     */
    fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T): T {
        val claims = extractAllClaims(token)
        return claimsResolver(claims)
    }

    /**
     * 모든 클레임 추출
     */
    private fun extractAllClaims(token: String): Claims {
        return try {
            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .payload
        } catch (ex: Exception) {
            logger.error("토큰 파싱 실패: ${ex.message}")
            throw JwtAuthenticationException(AuthErrorStatus.INVALID_TOKEN)
        }
    }

    // ========== 토큰 검증 메서드들 ==========

    /**
     * 토큰 유효성 검사 (UserDetails와 함께)
     */
    fun validateToken(token: String, userDetails: UserDetails): Boolean {
        return try {
            val username = extractUsername(token)
            val tokenType = extractTokenType(token)

            username == userDetails.username &&
                    !isTokenExpired(token) &&
                    tokenType == TokenType.ACCESS
        } catch (e: Exception) {
            logger.warn("토큰 검증 실패: ${e.message}")
            false
        }
    }

    /**
     * 토큰 유효성 검사 (사용자명만)
     */
    fun validateToken(token: String, username: String): Boolean {
        return try {
            val tokenUsername = extractUsername(token)
            tokenUsername == username && !isTokenExpired(token)
        } catch (e: Exception) {
            logger.warn("토큰 검증 실패: ${e.message}")
            false
        }
    }

    /**
     * Access Token 검증
     */
    fun validateAccessToken(token: String): Boolean {
        return try {
            val tokenType = extractTokenType(token)
            !isTokenExpired(token) && tokenType == TokenType.ACCESS
        } catch (e: Exception) {
            logger.warn("Access Token 검증 실패: ${e.message}")
            false
        }
    }

    /**
     * Refresh Token 검증
     */
    fun validateRefreshToken(token: String): Boolean {
        return try {
            val tokenType = extractTokenType(token)
            !isTokenExpired(token) && tokenType == TokenType.REFRESH
        } catch (e: Exception) {
            logger.warn("Refresh Token 검증 실패: ${e.message}")
            false
        }
    }

    /**
     * 토큰 만료 확인
     */
    private fun isTokenExpired(token: String): Boolean {
        return try {
            extractExpiration(token).before(Date())
        } catch (e: Exception) {
            logger.warn("토큰 만료 시간 확인 실패: ${e.message}")
            true // 에러 시 만료된 것으로 처리
        }
    }

    // ========== 유틸리티 메서드들 ==========

    /**
     * 토큰의 남은 유효시간 (밀리초)
     */
    fun getTokenRemainingTime(token: String): Long {
        return try {
            val expiration = extractExpiration(token)
            val now = Date()
            maxOf(0, expiration.time - now.time)
        } catch (e: Exception) {
            logger.warn("토큰 남은 시간 계산 실패: ${e.message}")
            0
        }
    }

    /**
     * Bearer 토큰에서 실제 토큰 추출
     */
    fun extractTokenFromBearer(bearerToken: String?): String? {
        return if (bearerToken?.startsWith("Bearer ") == true) {
            bearerToken.substring(7)
        } else null
    }

    /**
     * 토큰 정보 요약 (디버깅용)
     */
    fun getTokenInfo(token: String): TokenInfo? {
        return try {
            TokenInfo(
                username = extractUsername(token),
                tokenType = extractTokenType(token),
                issuedAt = extractIssuedAt(token),
                expiration = extractExpiration(token),
                isExpired = isTokenExpired(token),
                remainingTime = getTokenRemainingTime(token)
            )
        } catch (e: Exception) {
            logger.warn("토큰 정보 추출 실패: ${e.message}")
            null
        }
    }
}

/**
 * 토큰 정보 데이터 클래스
 */
data class TokenInfo(
    val username: String,
    val tokenType: TokenType?,
    val issuedAt: Date,
    val expiration: Date,
    val isExpired: Boolean,
    val remainingTime: Long
)
