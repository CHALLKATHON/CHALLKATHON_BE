package com.challkathon.demo.auth.dto.response

import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.challkathon.demo.domain.user.entity.enums.Role

data class UserInfoResponse(
    val id: Long,
    val email: String,
    val username: String,
    val role: Role,
    val provider: AuthProvider
)