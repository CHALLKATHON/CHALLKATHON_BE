package com.challkathon.demo.domain.user.repository

import com.challkathon.demo.domain.user.entity.User
import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface UserRepository : JpaRepository<User, Long> {
    fun findByEmail(email: String): Optional<User>
    fun existsByEmail(email: String): Boolean
    fun findByEmailAndAuthProvider(email: String, provider: AuthProvider): Optional<User>
}