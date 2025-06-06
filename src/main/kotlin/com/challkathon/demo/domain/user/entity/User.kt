package com.challkathon.demo.domain.user.entity

import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.challkathon.demo.domain.user.entity.enums.Role
import com.challkathon.demo.global.common.BaseEntity
import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
@Table(
    name = "`user`",
    indexes = [
        Index(name = "idx_user_email", columnList = "email"),
        Index(name = "idx_user_email_provider", columnList = "email, auth_provider")
    ],
    uniqueConstraints = [
        UniqueConstraint(columnNames = ["email", "auth_provider"])
    ]
)
class User(
    @Column(nullable = false, length = 100)
    var email: String,
    
    @Column(nullable = false, length = 50)
    var username: String,
    
    @Column(nullable = true)
    var password: String? = null,
    
    @Column(name = "provider_id", length = 100)
    var providerId: String? = null,
    
    @Column(name = "profile_image_url", length = 500)
    var profileImageUrl: String? = null,
    
    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider", nullable = false, length = 20)
    var authProvider: AuthProvider = AuthProvider.LOCAL,
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    var role: Role = Role.USER,
    
    @Column(name = "last_login_at")
    var lastLoginAt: LocalDateTime? = null,
    
    @Column(name = "email_verified")
    var emailVerified: Boolean = false,
    
    @Column(name = "is_active")
    var isActive: Boolean = true
) : BaseEntity() {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    val id: Long = 0
    
    // 편의 메서드들
    fun updateLastLogin() {
        this.lastLoginAt = LocalDateTime.now()
    }
    
    fun updateProfile(username: String?, profileImageUrl: String?) {
        username?.let { this.username = it }
        profileImageUrl?.let { this.profileImageUrl = it }
    }
    
    fun deactivate() {
        this.isActive = false
    }
    
    fun activate() {
        this.isActive = true
    }
    
    fun verifyEmail() {
        this.emailVerified = true
    }
    
    companion object {
        fun createLocalUser(
            email: String,
            username: String,
            encodedPassword: String
        ): User {
            return User(
                email = email,
                username = username,
                password = encodedPassword,
                authProvider = AuthProvider.LOCAL,
                emailVerified = false
            )
        }
        
        fun createOAuth2User(
            email: String,
            username: String,
            authProvider: AuthProvider,
            providerId: String,
            profileImageUrl: String? = null
        ): User {
            return User(
                email = email,
                username = username,
                password = null,
                providerId = providerId,
                profileImageUrl = profileImageUrl,
                authProvider = authProvider,
                emailVerified = true // OAuth2 providers usually verify email
            )
        }
    }
}