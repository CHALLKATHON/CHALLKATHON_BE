package com.challkathon.demo.auth.dto.response

import com.challkathon.demo.domain.user.entity.enums.AuthProvider
import com.challkathon.demo.domain.user.entity.enums.Role
import io.swagger.v3.oas.annotations.media.Schema
import jakarta.validation.constraints.NotBlank

@Schema(description = "인증 응답 DTO")
data class AuthResponse(
    @Schema(description = "액세스 토큰", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    val accessToken: String,
    
    @Schema(description = "리프레시 토큰", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    val refreshToken: String,
    
    @Schema(description = "토큰 타입", example = "Bearer")
    val tokenType: String = "Bearer",
    
    @Schema(description = "액세스 토큰 만료 시간(초)", example = "3600")
    val expiresIn: Long,
    
    @Schema(description = "사용자 정보")
    val user: UserInfoResponse
)

@Schema(description = "토큰 갱신 요청 DTO")
data class RefreshTokenRequest(
    @field:NotBlank(message = "리프레시 토큰은 필수입니다")
    @Schema(description = "리프레시 토큰", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    val refreshToken: String
)

@Schema(description = "토큰 정보 응답 DTO")
data class TokenInfoResponse(
    @Schema(description = "사용자명", example = "user@example.com")
    val username: String,
    
    @Schema(description = "토큰 타입", example = "ACCESS")
    val tokenType: String,
    
    @Schema(description = "발급 시간", example = "2024-01-01T00:00:00")
    val issuedAt: String,
    
    @Schema(description = "만료 시간", example = "2024-01-01T01:00:00")
    val expiration: String,
    
    @Schema(description = "만료 여부", example = "false")
    val isExpired: Boolean,
    
    @Schema(description = "남은 시간(초)", example = "3600")
    val remainingTimeSeconds: Long
)