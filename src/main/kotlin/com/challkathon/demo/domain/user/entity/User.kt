package com.challkathon.demo.domain.user.entity

import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.challkathon.demo.domain.user.entity.enums.Role
import com.challkathon.demo.global.common.BaseEntity
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table

@Entity
@Table(name = "`user`")
class User(

    var email: String = "",

    var username: String = "",

    var password: String = "",

    @Enumerated(EnumType.STRING)
    var authProvider: AuthProvider = AuthProvider.LOCAL,

    @Enumerated(EnumType.STRING)
    var role: Role = Role.USER,

    ) : BaseEntity() {
        
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    val id: Long = 0

}