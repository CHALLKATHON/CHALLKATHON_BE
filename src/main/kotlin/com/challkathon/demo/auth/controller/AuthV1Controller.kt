package com.challkathon.demo.auth.controller

import com.challkathon.demo.auth.dto.request.SignInRequest
import com.challkathon.demo.auth.dto.request.SignUpRequest
import com.challkathon.demo.auth.dto.response.AuthResponse
import com.challkathon.demo.auth.dto.response.SignInResponse
import com.challkathon.demo.auth.dto.response.RefreshTokenRequest
import com.challkathon.demo.auth.dto.response.TokenInfoResponse
import com.challkathon.demo.auth.service.AuthService
import com.challkathon.demo.auth.service.AuthResult
import com.challkathon.demo.auth.util.TokenCookieUtil
import com.challkathon.demo.global.common.BaseResponse
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletResponse
import jakarta.validation.Valid
import mu.KotlinLogging
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.web.bind.annotation.*

private val log = KotlinLogging.logger {}

@Tag(name = "인증 API", description = "회원가입, 로그인, 토큰 갱신 등 인증 관련 API")
@RestController
@RequestMapping("/api/v1/auth")
class AuthV1Controller(
    private val authService: AuthService,
    private val tokenCookieUtil: TokenCookieUtil
) {

    @Operation(summary = "회원가입", description = "이메일과 비밀번호로 회원가입을 진행합니다")
    @ApiResponses(
        ApiResponse(responseCode = "201", description = "회원가입 성공"),
        ApiResponse(responseCode = "400", description = "잘못된 요청"),
        ApiResponse(responseCode = "409", description = "이미 존재하는 이메일")
    )
    @PostMapping("/signup")
    fun signUp(
        @Valid @RequestBody signUpRequest: SignUpRequest,
        response: HttpServletResponse
    ): ResponseEntity<BaseResponse<SignInResponse>> {
        log.info { "회원가입 요청: ${signUpRequest.email}" }
        
        val authResult = authService.signUp(signUpRequest)
        
        // 헤더에 토큰 설정
        response.setHeader("Authorization", "Bearer ${authResult.accessToken}")
        response.setHeader("X-Refresh-Token", authResult.refreshToken)
        
        // 쿠키에도 토큰 설정 (선택적)
        tokenCookieUtil.addTokenCookies(response, authResult.accessToken, authResult.refreshToken)
        
        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(BaseResponse.onSuccessCreate(SignInResponse(user = authResult.userInfo)))
    }

    @Operation(summary = "로그인", description = "이메일과 비밀번호로 로그인을 진행합니다")
    @ApiResponses(
        ApiResponse(responseCode = "200", description = "로그인 성공"),
        ApiResponse(responseCode = "401", description = "인증 실패")
    )
    @PostMapping("/signin")
    fun signIn(
        @Valid @RequestBody signInRequest: SignInRequest,
        response: HttpServletResponse
    ): ResponseEntity<BaseResponse<SignInResponse>> {
        log.info { "로그인 요청: ${signInRequest.email}" }
        
        val authResult = authService.signIn(signInRequest)
        
        // 헤더에 토큰 설정
        response.setHeader("Authorization", "Bearer ${authResult.accessToken}")
        response.setHeader("X-Refresh-Token", authResult.refreshToken)
        
        // 쿠키에도 토큰 설정 (선택적)
        tokenCookieUtil.addTokenCookies(response, authResult.accessToken, authResult.refreshToken)
        
        return ResponseEntity.ok(BaseResponse.onSuccess(SignInResponse(user = authResult.userInfo)))
    }

    @Operation(summary = "토큰 갱신", description = "리프레시 토큰으로 새로운 액세스 토큰을 발급받습니다")
    @ApiResponses(
        ApiResponse(responseCode = "200", description = "토큰 갱신 성공"),
        ApiResponse(responseCode = "401", description = "유효하지 않은 리프레시 토큰")
    )
    @PostMapping("/refresh")
    fun refreshToken(
        @Valid @RequestBody refreshTokenRequest: RefreshTokenRequest,
        response: HttpServletResponse
    ): ResponseEntity<BaseResponse<SignInResponse>> {
        log.info { "토큰 갱신 요청" }
        
        val authResult = authService.refreshToken(refreshTokenRequest.refreshToken)
        
        // 헤더에 새로운 토큰 설정
        response.setHeader("Authorization", "Bearer ${authResult.accessToken}")
        response.setHeader("X-Refresh-Token", authResult.refreshToken)
        
        // 쿠키에도 새로운 토큰 설정 (선택적)
        tokenCookieUtil.addTokenCookies(response, authResult.accessToken, authResult.refreshToken)
        
        return ResponseEntity.ok(BaseResponse.onSuccess(SignInResponse(user = authResult.userInfo)))
    }

    @Operation(
        summary = "로그아웃", 
        description = "로그아웃을 진행합니다 (클라이언트 측에서 토큰 삭제)",
        security = [SecurityRequirement(name = "bearerAuth")]
    )
    @PostMapping("/logout")
    fun logout(
        @AuthenticationPrincipal userDetails: UserDetails,
        response: HttpServletResponse
    ): ResponseEntity<BaseResponse<String>> {
        log.info { "로그아웃 요청: ${userDetails.username}" }
        
        // 쿠키 삭제
        tokenCookieUtil.deleteTokenCookies(response)
        
        return ResponseEntity.ok(BaseResponse.onSuccess("로그아웃 되었습니다"))
    }

    @Operation(
        summary = "토큰 정보 조회", 
        description = "현재 액세스 토큰의 상세 정보를 조회합니다",
        security = [SecurityRequirement(name = "bearerAuth")]
    )
    @GetMapping("/token-info")
    fun getTokenInfo(
        @Parameter(description = "Bearer 토큰", required = true)
        @RequestHeader("Authorization") bearerToken: String,
        @AuthenticationPrincipal userDetails: UserDetails
    ): ResponseEntity<BaseResponse<TokenInfoResponse?>> {
        log.info { "토큰 정보 조회: ${userDetails.username}" }
        
        val token = bearerToken.substring(7) // "Bearer " 제거
        val tokenInfo = authService.getTokenInfo(token)
        
        return ResponseEntity.ok(BaseResponse.onSuccess(tokenInfo))
    }

    @Operation(
        summary = "현재 사용자 정보", 
        description = "현재 로그인한 사용자의 정보를 조회합니다",
        security = [SecurityRequirement(name = "bearerAuth")]
    )
    @GetMapping("/me")
    fun getCurrentUser(
        @AuthenticationPrincipal userDetails: UserDetails
    ): ResponseEntity<BaseResponse<Map<String, Any>>> {
        log.info { "현재 사용자 정보 조회: ${userDetails.username}" }
        
        val userInfo = mapOf(
            "email" to userDetails.username,
            "authorities" to userDetails.authorities.map { it.authority }
        )
        
        return ResponseEntity.ok(BaseResponse.onSuccess(userInfo))
    }
}