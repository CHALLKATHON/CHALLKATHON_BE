import com.challkathon.demo.auth.dto.response.UserInfoResponse

data class AuthResult(
    val accessToken: String,
    val refreshToken: String,
    val userInfo: UserInfoResponse
)