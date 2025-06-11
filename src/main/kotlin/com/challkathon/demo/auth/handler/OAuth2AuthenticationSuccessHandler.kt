package com.challkathon.demo.auth.handler

import com.challkathon.demo.auth.provider.JwtProvider
import com.challkathon.demo.auth.security.UserPrincipal
import com.challkathon.demo.auth.util.TokenCookieUtil
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import mu.KotlinLogging
import org.springframework.web.util.UriComponentsBuilder

private val log = KotlinLogging.logger {}

@Component
class OAuth2AuthenticationSuccessHandler(
    private val jwtProvider: JwtProvider,
    private val tokenCookieUtil: TokenCookieUtil
) : SimpleUrlAuthenticationSuccessHandler() {

    @Value("\${app.oauth2.authorized-redirect-uris:http://localhost:3000/oauth2/redirect}")
    private lateinit var authorizedRedirectUris: String

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val targetUrl = determineTargetUrl(request, response, authentication)

        if (response.isCommitted) {
            logger.debug("응답이 이미 커밋되었습니다. $targetUrl 로 리다이렉트할 수 없습니다")
            return
        }

        clearAuthenticationAttributes(request)
        redirectStrategy.sendRedirect(request, response, targetUrl)
    }

    override fun determineTargetUrl(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ): String {
        val redirectUri = getRedirectUri(request)

        val targetUrl = redirectUri ?: "/oauth2/redirect"


        // authentication.principal은 OAuth2UserService가 반환한 UserPrincipal
        val userPrincipal = authentication.principal as UserPrincipal
        val accessToken = jwtProvider.generateAccessToken(userPrincipal)
        val refreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

        // 헤더와 쿠키에 토큰 설정
        tokenCookieUtil.addTokenCookies(response, accessToken, refreshToken)
        
        // 테스트 환경인 경우 헤더 설정 확인
        if (targetUrl.contains("localhost:8080")) {
            log.info { "OAuth2 로그인 성공 - 토큰 헤더 설정 완료" }
        }

        return UriComponentsBuilder.fromUriString(targetUrl)
            .queryParam("token", accessToken)  // 짧은 파라미터명 사용
            .build().toUriString()
    }

    private fun getRedirectUri(request: HttpServletRequest): String? {
        return request.getParameter("redirect_uri")
    }
}