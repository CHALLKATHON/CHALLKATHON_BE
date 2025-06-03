package com.challkathon.demo.auth.service

import com.challkathon.demo.auth.excepetion.OAuth2AuthenticationException
import com.challkathon.demo.auth.excepetion.code.AuthErrorStatus
import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.example.auth.security.UserPrincipal
import com.example.auth.service.AuthService
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service

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
            val oauth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                userRequest.clientRegistration.registrationId,
                oauth2User.attributes
            )

            val user = authService.processOAuthPostLogin(
                email = oauth2UserInfo.email,
                name = oauth2UserInfo.name,
                provider = oauth2UserInfo.provider,
                providerId = oauth2UserInfo.id
            )

            return UserPrincipal.create(user, oauth2User.attributes)
        } catch (e: Exception) {
            throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_AUTHENTICATION_FAILED)
        }
    }
}

// OAuth2 사용자 정보 추상화
abstract class OAuth2UserInfo(
    protected val attributes: Map<String, Any>
) {
    abstract val id: String
    abstract val name: String
    abstract val email: String
    abstract val provider: AuthProvider
}

// Kakao OAuth2 사용자 정보
class KakaoOAuth2UserInfo(attributes: Map<String, Any>) : OAuth2UserInfo(attributes) {
    override val id: String = attributes["id"]?.toString()
        ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)

    override val name: String = run {
        val kakaoAccount = attributes["kakao_account"] as? Map<String, Any>
            ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
        val profile = kakaoAccount["profile"] as? Map<String, Any>
            ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
        profile["nickname"] as? String
            ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
    }

    override val email: String = run {
        val kakaoAccount = attributes["kakao_account"] as? Map<String, Any>
            ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
        kakaoAccount["email"] as? String
            ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
    }

    override val provider: AuthProvider = AuthProvider.KAKAO
}

// Naver OAuth2 사용자 정보
class NaverOAuth2UserInfo(attributes: Map<String, Any>) : OAuth2UserInfo(attributes) {
    private val response = attributes["response"] as? Map<String, Any>
        ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)

    override val id: String = response["id"] as? String
        ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
    override val name: String = response["name"] as? String
        ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
    override val email: String = response["email"] as? String
        ?: throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_USER_INFO_RETRIEVAL_FAILED)
    override val provider: AuthProvider = AuthProvider.NAVER
}

// OAuth2 사용자 정보 팩토리
object OAuth2UserInfoFactory {
    fun getOAuth2UserInfo(registrationId: String, attributes: Map<String, Any>): OAuth2UserInfo {
        return when (registrationId.lowercase()) {
            "kakao" -> KakaoOAuth2UserInfo(attributes)
            "naver" -> NaverOAuth2UserInfo(attributes)
            else -> throw OAuth2AuthenticationException(AuthErrorStatus._OAUTH2_PROVIDER_NOT_SUPPORTED)
        }
    }
}