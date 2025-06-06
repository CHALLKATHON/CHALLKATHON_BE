package com.challkathon.demo.auth.service

import com.challkathon.demo.auth.dto.OAuth2UserInfo
import com.challkathon.demo.auth.exception.OAuth2AuthenticationException
import com.challkathon.demo.auth.exception.code.AuthErrorStatus
import com.challkathon.demo.auth.security.UserPrincipal
import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import mu.KotlinLogging
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service

private val log = KotlinLogging.logger {}

@Service
class CustomOAuth2UserService(
    private val authService: AuthService
) : DefaultOAuth2UserService() {

    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        val oauth2User = super.loadUser(userRequest)
        
        return processOAuth2User(userRequest, oauth2User)
    }

    private fun processOAuth2User(userRequest: OAuth2UserRequest, oauth2User: OAuth2User): OAuth2User {
        try {
            val registrationId = userRequest.clientRegistration.registrationId
            val attributes = oauth2User.attributes
            
            log.info { "OAuth2 로그인 시도: $registrationId" }
            
            // Provider에 따른 OAuth2UserInfo 생성
            val provider = when (registrationId.lowercase()) {
                "google" -> AuthProvider.GOOGLE
                "github" -> AuthProvider.GITHUB
                "kakao" -> AuthProvider.KAKAO
                "naver" -> AuthProvider.NAVER
                else -> throw OAuth2AuthenticationException(
                    AuthErrorStatus._OAUTH2_PROVIDER_NOT_SUPPORTED,
                    "지원하지 않는 OAuth2 provider: $registrationId"
                )
            }
            
            val oauth2UserInfo = OAuth2UserInfo.of(provider, attributes)
            
            // 사용자 정보 처리 (신규 가입 또는 기존 사용자 업데이트)
            val user = authService.processOAuthPostLogin(
                email = oauth2UserInfo.email,
                name = oauth2UserInfo.name,
                provider = oauth2UserInfo.provider,
                providerId = oauth2UserInfo.id,
                profileImageUrl = oauth2UserInfo.imageUrl
            )
            
            log.info { "OAuth2 로그인 성공: ${user.email} (${user.authProvider})" }
            
            return UserPrincipal.create(user, attributes)
        } catch (e: OAuth2AuthenticationException) {
            log.error(e) { "OAuth2 인증 실패" }
            throw e
        } catch (e: Exception) {
            log.error(e) { "OAuth2 사용자 처리 중 오류 발생" }
            throw OAuth2AuthenticationException(
                AuthErrorStatus._OAUTH2_AUTHENTICATION_FAILED,
                e.message
            )
        }
    }
}