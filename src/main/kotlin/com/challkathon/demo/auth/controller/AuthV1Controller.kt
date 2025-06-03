package com.example.auth.controller

import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1/auth")
class AuthV1Controller(
    private val authService: AuthService
) {

    @PostMapping("/signup")
    fun signUp(@Valid @RequestBody signUpRequest: SignUpRequest): ResponseEntity<AuthResponse> {
        return try {
            val authResponse = authService.signUp(signUpRequest)
            ResponseEntity.ok(authResponse)
        } catch (e: Exception) {
            ResponseEntity.badRequest().build()
        }
    }

    @PostMapping("/signin")
    fun signIn(@Valid @RequestBody signInRequest: SignInRequest): ResponseEntity<AuthResponse> {
        return try {
            val authResponse = authService.signIn(signInRequest)
            ResponseEntity.ok(authResponse)
        } catch (e: Exception) {
            ResponseEntity.badRequest().build()
        }
    }


}