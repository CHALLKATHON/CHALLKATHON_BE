package com.example.auth.security

import com.challkathon.demo.domain.user.entity.User
import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.example.auth.entity.Role
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 * Spring Security의 UserDetails 인터페이스를 구현하는 래퍼 클래스
 * User 엔티티를 조합(Composition)으로 사용하여 보안 컨텍스트에서 사용
 */
class UserPrincipal private constructor(
    private val user: User,
    private val attributes: Map<String, Any> = emptyMap()
) : UserDetails, OAuth2User {

    companion object {
        /**
         * 일반 로그인용 UserPrincipal 생성
         */
        fun create(user: User): UserPrincipal {
            return UserPrincipal(user)
        }

        /**
         * OAuth2 로그인용 UserPrincipal 생성
         */
        fun create(user: User, attributes: Map<String, Any>): UserPrincipal {
            return UserPrincipal(user, attributes)
        }
    }

    // User 엔티티의 정보에 접근할 수 있는 프로퍼티들
    val id: Long get() = user.id
    val email: String get() = user.email
    val username: String get() = user.username
    val role: Role get() = user.role
    val provider: AuthProvider get() = user.provider

    /**
     * 원본 User 엔티티 반환 (비즈니스 로직에서 필요시 사용)
     */
    fun getUser(): User = user

    // ========== UserDetails 인터페이스 구현 ==========
    override fun getUsername(): String = user.email
    override fun getPassword(): String? = user.password
    override fun getAuthorities(): Collection<GrantedAuthority> {
        return listOf(SimpleGrantedAuthority("ROLE_${user.role.name}"))
    }

    override fun isAccountNonExpired(): Boolean = true
    override fun isAccountNonLocked(): Boolean = true
    override fun isCredentialsNonExpired(): Boolean = true
    override fun isEnabled(): Boolean = true

    // ========== OAuth2User 인터페이스 구현 ==========
    override fun getName(): String = user.id.toString() // OAuth2User의 getName()
    override fun getAttributes(): Map<String, Any> = attributes

    // ========== 편의 메서드들 ==========
    fun isLocalUser(): Boolean = user.isLocalUser()
    fun isSocialUser(): Boolean = user.isSocialUser()
    fun hasPassword(): Boolean = user.hasPassword()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UserPrincipal) return false
        return user.id == other.user.id
    }

    override fun hashCode(): Int {
        return user.id.hashCode()
    }

    override fun toString(): String {
        return "UserPrincipal(id=${user.id}, email=${user.email}, role=${user.role})"
    }
}