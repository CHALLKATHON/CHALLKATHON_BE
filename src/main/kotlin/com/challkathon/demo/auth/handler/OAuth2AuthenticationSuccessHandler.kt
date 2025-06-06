package com.challkathon.demo.auth.handler

import com.challkathon.demo.auth.provider.JwtProvider
import com.challkathon.demo.auth.security.UserPrincipal
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

@Component
class OAuth2AuthenticationSuccessHandler(
    private val jwtProvider: JwtProvider
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

        if (redirectUri != null && !isAuthorizedRedirectUri(redirectUri)) {
            throw IllegalArgumentException("승인되지 않은 리다이렉트 URI입니다")
        }

        val targetUrl = redirectUri ?: defaultTargetUrl

        // authentication.principal은 OAuth2UserService가 반환한 UserPrincipal
        val userPrincipal = authentication.principal as UserPrincipal
        val accessToken = jwtProvider.generateAccessToken(userPrincipal)
        val refreshToken = jwtProvider.generateRefreshToken(userPrincipal.username)

        return UriComponentsBuilder.fromUriString(targetUrl)
            .queryParam("accessToken", accessToken)
            .queryParam("refreshToken", refreshToken)
            .queryParam("tokenType", "Bearer")
            .build().toUriString()
    }

    private fun getRedirectUri(request: HttpServletRequest): String? {
        return request.getParameter("redirect_uri")
    }

    private fun isAuthorizedRedirectUri(uri: String): Boolean {
        val clientRedirectUri = URI.create(uri)

        return authorizedRedirectUris.split(",").any { authorizedRedirectUri ->
            val authorizedURI = URI.create(authorizedRedirectUri.trim())

            authorizedURI.host.equals(clientRedirectUri.host, ignoreCase = true) &&
                    authorizedURI.port == clientRedirectUri.port
        }
    }
}