package com.challkathon.demo.auth.filter

import com.challkathon.demo.auth.provider.JwtProvider
import com.challkathon.demo.auth.service.CustomUserDetailsService
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.util.StringUtils
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val jwtProvider: JwtProvider,
    private val userDetailsService: CustomUserDetailsService
) : OncePerRequestFilter() {

    private val logger = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            val jwt = getJwtFromRequest(request)

            if (StringUtils.hasText(jwt)) {
                // Access Token 유효성 검사 먼저 수행
                if (!jwtProvider.validateAccessToken(jwt!!)) {
                    logger.debug("유효하지 않은 Access Token입니다")
                    filterChain.doFilter(request, response)
                    return
                }

                val username = jwtProvider.extractUsername(jwt)

                if (SecurityContextHolder.getContext().authentication == null) {
                    // UserDetailsService를 통해 UserPrincipal 획득
                    val userDetails = userDetailsService.loadUserByUsername(username)

                    // 추가 검증: UserDetails와 함께 토큰 검증
                    if (jwtProvider.validateToken(jwt, userDetails)) {
                        val authentication = UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.authorities
                        )
                        authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
                        SecurityContextHolder.getContext().authentication = authentication

                    }
                }
            }
        } catch (ex: Exception) {
            logger.error("사용자 인증을 설정할 수 없습니다", ex)
            // 예외 발생 시 SecurityContext를 비워서 인증 실패 처리
            SecurityContextHolder.clearContext()
        }

        filterChain.doFilter(request, response)
    }

    /**
     * Authorization 헤더에서 JWT 토큰 추출
     */
    private fun getJwtFromRequest(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader("Authorization")
        return jwtProvider.extractTokenFromBearer(bearerToken)
    }
}