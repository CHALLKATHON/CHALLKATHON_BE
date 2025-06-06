package com.challkathon.demo.auth.util

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class TokenCookieUtil {

    @Value("\${app.cookie.refresh-token.name:refreshToken}")
    private lateinit var refreshTokenCookieName: String

    @Value("\${app.cookie.refresh-token.max-age:604800}") // 7일 (초 단위)
    private var refreshTokenMaxAge: Int = 604800

    @Value("\${app.cookie.domain:localhost}")
    private lateinit var cookieDomain: String

    @Value("\${app.cookie.secure:false}") // 개발환경에서는 false, 운영환경에서는 true
    private var cookieSecure: Boolean = false

    companion object {
        const val ACCESS_TOKEN_HEADER = "Authorization"
        const val TOKEN_PREFIX = "Bearer "
    }

    /**
     * Access Token을 응답 헤더에 설정
     */
    fun setAccessTokenHeader(response: HttpServletResponse, accessToken: String) {
        response.setHeader(ACCESS_TOKEN_HEADER, "$TOKEN_PREFIX$accessToken")
        // CORS를 위해 노출할 헤더 설정
        response.setHeader("Access-Control-Expose-Headers", ACCESS_TOKEN_HEADER)
    }

    /**
     * Refresh Token을 HttpOnly 쿠키에 설정
     */
    fun setRefreshTokenCookie(response: HttpServletResponse, refreshToken: String) {
        val cookie = Cookie(refreshTokenCookieName, refreshToken).apply {
            maxAge = refreshTokenMaxAge
            isHttpOnly = true  // JavaScript 접근 차단 (XSS 방지)
            secure = cookieSecure  // HTTPS에서만 전송 (운영환경)
            path = "/"  // 모든 경로에서 접근 가능
            // domain = cookieDomain  // 도메인 설정 (필요시)
        }
        response.addCookie(cookie)
    }

    /**
     * 요청에서 Refresh Token 쿠키 추출
     */
    fun getRefreshTokenFromCookie(request: HttpServletRequest): String? {
        return request.cookies
            ?.find { it.name == refreshTokenCookieName }
            ?.value
    }

    /**
     * 요청 헤더에서 Access Token 추출
     */
    fun getAccessTokenFromHeader(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader(ACCESS_TOKEN_HEADER)
        return if (bearerToken?.startsWith(TOKEN_PREFIX) == true) {
            bearerToken.substring(TOKEN_PREFIX.length)
        } else null
    }

    /**
     * Refresh Token 쿠키 삭제 (로그아웃 시 사용)
     */
    fun deleteRefreshTokenCookie(response: HttpServletResponse) {
        val cookie = Cookie(refreshTokenCookieName, null).apply {
            maxAge = 0  // 즉시 만료
            isHttpOnly = true
            secure = cookieSecure
            path = "/"
        }
        response.addCookie(cookie)
    }

    /**
     * 모든 토큰 정리 (로그아웃 시 사용)
     */
    fun clearAllTokens(response: HttpServletResponse) {
        // Access Token 헤더 제거
        response.setHeader(ACCESS_TOKEN_HEADER, "")

        // Refresh Token 쿠키 삭제
        deleteRefreshTokenCookie(response)
    }

    /**
     * 토큰 설정 (회원가입, 로그인 시 사용)
     */
    fun setTokens(response: HttpServletResponse, accessToken: String, refreshToken: String) {
        setAccessTokenHeader(response, accessToken)
        setRefreshTokenCookie(response, refreshToken)
    }
    
    /**
     * 쿠키에 토큰 추가 (별칭 메서드)
     */
    fun addTokenCookies(response: HttpServletResponse, accessToken: String, refreshToken: String) {
        setTokens(response, accessToken, refreshToken)
    }
    
    /**
     * 토큰 쿠키 삭제 (별칭 메서드)
     */
    fun deleteTokenCookies(response: HttpServletResponse) {
        clearAllTokens(response)
    }
}