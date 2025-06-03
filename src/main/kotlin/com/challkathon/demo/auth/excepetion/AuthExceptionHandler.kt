package com.challkathon.demo.auth.excepetion

import com.challkathon.demo.auth.excepetion.code.AuthErrorStatus
import com.challkathon.demo.global.common.BaseResponse
import com.challkathon.demo.global.exception.BaseException
import com.challkathon.demo.global.exception.code.BaseCode
import com.challkathon.demo.global.exception.code.GlobalErrorStatus
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.SignatureException
import io.jsonwebtoken.UnsupportedJwtException
import mu.KotlinLogging
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.RestControllerAdvice

private val log = KotlinLogging.logger {}

@RestControllerAdvice(annotations = [RestController::class])
class AuthExceptionHandler {

    /**
     * JWT 관련 예외 처리
     */
    @ExceptionHandler(JwtAuthenticationException::class)
    fun handleJwtAuthenticationException(e: JwtAuthenticationException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleJwtAuthenticationException] JWT 인증 실패: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._JWT_AUTHENTICATION_FAILED.getCode())
    }

    @ExceptionHandler(ExpiredJwtException::class)
    fun handleExpiredJwtException(e: ExpiredJwtException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleExpiredJwtException] JWT 토큰 만료: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._TOKEN_EXPIRED.getCode())
    }

    @ExceptionHandler(MalformedJwtException::class)
    fun handleMalformedJwtException(e: MalformedJwtException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleMalformedJwtException] 잘못된 JWT 형식: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._TOKEN_MALFORMED.getCode())
    }

    @ExceptionHandler(UnsupportedJwtException::class)
    fun handleUnsupportedJwtException(e: UnsupportedJwtException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleUnsupportedJwtException] 지원하지 않는 JWT: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._TOKEN_UNSUPPORTED.getCode())
    }

    @ExceptionHandler(SignatureException::class)
    fun handleSignatureException(e: SignatureException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleSignatureException] JWT 서명 검증 실패: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._TOKEN_SIGNATURE_INVALID.getCode())
    }

    /**
     * 인증 관련 예외 처리
     */
    @ExceptionHandler(BadCredentialsException::class)
    fun handleBadCredentialsException(e: BadCredentialsException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleBadCredentialsException] 잘못된 자격 증명: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._BAD_CREDENTIALS.getCode())
    }

    @ExceptionHandler(UsernameNotFoundException::class)
    fun handleUsernameNotFoundException(e: UsernameNotFoundException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleUsernameNotFoundException] 사용자를 찾을 수 없음: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._USER_NOT_FOUND.getCode())
    }

    @ExceptionHandler(DisabledException::class)
    fun handleDisabledException(e: DisabledException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleDisabledException] 비활성화된 계정: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._ACCOUNT_DISABLED.getCode())
    }

    @ExceptionHandler(LockedException::class)
    fun handleLockedException(e: LockedException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleLockedException] 잠긴 계정: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._ACCOUNT_LOCKED.getCode())
    }

    @ExceptionHandler(AuthenticationException::class)
    fun handleAuthenticationException(e: AuthenticationException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleAuthenticationException] 인증 실패: ${e.message}" }
        return handleExceptionInternal(AuthErrorStatus._AUTHENTICATION_FAILED.getCode())
    }

    /**
     * 커스텀 인증 예외 처리
     */
    @ExceptionHandler(EmailAlreadyExistsException::class)
    fun handleEmailAlreadyExistsException(e: EmailAlreadyExistsException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleEmailAlreadyExistsException] 이메일 중복: ${e.message}" }
        return handleExceptionInternal(e.getErrorCode())
    }

    @ExceptionHandler(TokenExpiredException::class)
    fun handleTokenExpiredException(e: TokenExpiredException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleTokenExpiredException] 토큰 만료: ${e.message}" }
        return handleExceptionInternal(e.getErrorCode())
    }

    @ExceptionHandler(RefreshTokenException::class)
    fun handleRefreshTokenException(e: RefreshTokenException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleRefreshTokenException] Refresh Token 오류: ${e.message}" }
        return handleExceptionInternal(e.getErrorCode())
    }

    @ExceptionHandler(OAuth2AuthenticationException::class)
    fun handleOAuth2AuthenticationException(e: OAuth2AuthenticationException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleOAuth2AuthenticationException] OAuth2 인증 실패: ${e.message}" }
        return handleExceptionInternal(e.getErrorCode())
    }

    @ExceptionHandler(InsufficientPrivilegesException::class)
    fun handleInsufficientPrivilegesException(e: InsufficientPrivilegesException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleInsufficientPrivilegesException] 권한 부족: ${e.message}" }
        return handleExceptionInternal(e.getErrorCode())
    }

    /**
     * 유효성 검사 예외 처리
     */
    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidationException(e: MethodArgumentNotValidException): ResponseEntity<BaseResponse<Map<String, String>>> {
        val errors = mutableMapOf<String, String>()

        e.bindingResult.allErrors.forEach { error ->
            val fieldName = (error as FieldError).field
            val message = error.defaultMessage ?: "유효하지 않은 값입니다"
            errors.merge(fieldName, message) { oldVal, newVal -> "$oldVal, $newVal" }
        }

        log.error(e) { "[handleValidationException] 입력 데이터 검증 실패: ${e.message}" }
        return handleExceptionInternalArgs(AuthErrorStatus._VALIDATION_FAILED.getCode(), errors)
    }

    /**
     * 기본 비즈니스 예외 처리
     */
    @ExceptionHandler(BaseException::class)
    fun handleBaseException(e: BaseException): ResponseEntity<BaseResponse<String>> {
        val errorCode = e.getErrorCode()
        log.error(e) { "[handleBaseException] 비즈니스 예외: ${e.message}" }
        return handleExceptionInternal(errorCode)
    }

    /**
     * 일반적인 런타임 예외 처리
     */
    @ExceptionHandler(RuntimeException::class)
    fun handleRuntimeException(e: RuntimeException): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleRuntimeException] 런타임 예외: ${e.message}" }
        return handleExceptionInternalFalse(
            GlobalErrorStatus._BAD_REQUEST.getCode(),
            e.message
        )
    }

    /**
     * 예상치 못한 예외 처리
     */
    @ExceptionHandler(Exception::class)
    fun handleGenericException(e: Exception): ResponseEntity<BaseResponse<String>> {
        log.error(e) { "[handleGenericException] 예상치 못한 예외: ${e.message}" }
        return handleExceptionInternalFalse(
            GlobalErrorStatus._INTERNAL_SERVER_ERROR.getCode(),
            e.message
        )
    }

    /**
     * ==============
     * 내부 메서드
     * ==============
     */
    private fun handleExceptionInternal(errorCode: BaseCode): ResponseEntity<BaseResponse<String>> {
        return ResponseEntity
            .status(errorCode.httpStatus)
            .body(BaseResponse.onFailure(errorCode.code, errorCode.message, null))
    }

    private fun handleExceptionInternalArgs(
        errorCode: BaseCode,
        errorArgs: Map<String, String>
    ): ResponseEntity<BaseResponse<Map<String, String>>> {
        return ResponseEntity
            .status(errorCode.httpStatus)
            .body(BaseResponse.onFailure(errorCode.code, errorCode.message, errorArgs))
    }

    private fun handleExceptionInternalFalse(
        errorCode: BaseCode,
        errorPoint: String?
    ): ResponseEntity<BaseResponse<String>> {
        return ResponseEntity
            .status(errorCode.httpStatus)
            .body(BaseResponse.onFailure(errorCode.code, errorCode.message, errorPoint))
    }
}

/**
 * 인증 관련 커스텀 예외 클래스들
 */
class JwtAuthenticationException(message: String) : BaseException(AuthErrorStatus._JWT_AUTHENTICATION_FAILED)

class EmailAlreadyExistsException(message: String) : BaseException(AuthErrorStatus._EMAIL_ALREADY_EXISTS)

class TokenExpiredException(message: String) : BaseException(AuthErrorStatus._TOKEN_EXPIRED)

class RefreshTokenException(authErrorStatus: AuthErrorStatus) : BaseException(authErrorStatus)

class OAuth2AuthenticationException(authErrorStatus: AuthErrorStatus) : BaseException(authErrorStatus)

class InsufficientPrivilegesException(authErrorStatus: AuthErrorStatus) : BaseException(authErrorStatus)