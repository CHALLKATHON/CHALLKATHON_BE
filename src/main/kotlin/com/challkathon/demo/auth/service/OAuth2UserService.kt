package com.challkathon.demo.auth.service

import com.challkathon.demo.domain.user.entity.User
import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.challkathon.demo.domain.user.repository.UserRepository
import mu.KotlinLogging
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

private val log = KotlinLogging.logger {}

/**
 * OAuth2 사용자 처리를 위한 별도 서비스
 * 순환 참조를 방지하기 위해 AuthService와 분리
 */
@Service
@Transactional
class OAuth2UserService(
    private val userRepository: UserRepository
) {
    
    /**
     * OAuth2 사용자 등록 또는 업데이트
     */
    fun processOAuthPostLogin(
        email: String,
        username: String,
        provider: AuthProvider,
        providerId: String,
        profileImageUrl: String? = null
    ): User {
        log.info { "OAuth2 로그인 처리: $email ($provider)" }

        val existingUser = userRepository.findByEmailAndAuthProvider(email, provider)

        return if (existingUser.isPresent) {
            // 기존 사용자 업데이트
            val user = existingUser.get()
            user.updateLastLogin()
            user.updateProfile(username, profileImageUrl)
            val updatedUser = userRepository.save(user)
            log.info { "기존 OAuth2 사용자 로그인: $email" }
            updatedUser
        } else {
            // 새 사용자 생성
            val newUser = User.createOAuth2User(
                email = email,
                username = username,
                authProvider = provider,
                providerId = providerId,
                profileImageUrl = profileImageUrl
            )
            val savedUser = userRepository.save(newUser)
            log.info { "새 OAuth2 사용자 생성: $email" }
            savedUser
        }
    }
}