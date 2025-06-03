package com.challkathon.demo.domain.user.entity.enums

enum class AuthProvider(
    val description: String
) {
    LOCAL("일반 로그인"),
    KAKAO("카카오 로그인"),
    NAVER("네이버 로그인")
}