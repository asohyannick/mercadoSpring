package com.mercado.mercadoSpring.controller.auth;
import com.google.firebase.auth.FirebaseAuthException;
import com.mercado.mercadoSpring.config.ApiResponseConfig;
import com.mercado.mercadoSpring.constants.user.UserRole;
import com.mercado.mercadoSpring.dto.auth.*;
import com.mercado.mercadoSpring.entity.auth.Auth;
import com.mercado.mercadoSpring.mappers.auth.AuthMapper;
import com.mercado.mercadoSpring.repository.auth.AuthRepository;
import com.mercado.mercadoSpring.service.auth.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/${API_VERSION}/users")
@RequiredArgsConstructor
@Tag(name = "Authentication and User Management Endpoints", description = "APIs for user authentication and management")
public class AuthController {
    private final AuthService authService;
    private final AuthRepository authRepository;
    private final AuthMapper authMapper;
    /**
     * User registration endpoint
     */
    @PostMapping("/register")
    @Operation(summary = "Register a new user with 2FA email verification")
    public ResponseEntity<ApiResponseConfig<ResponseDto>> register(@Valid @RequestBody RegistrationDto registrationDto) {
        ResponseDto responseDto = authService.register(registrationDto);
        ApiResponseConfig<ResponseDto> response = new ApiResponseConfig<>(
                "🎉 Registration successful! A 2FA verification code has been sent to your email. Please enter it within 5 minutes to activate your account.",
               responseDto
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-otp")
    @Operation(summary = "Verify 2FA OTP for a registered user")
    public ResponseEntity<ApiResponseConfig<Auth>> verifyOTP(
            @Valid @RequestBody OTPRequest otpRequest) {

        // Delegate to service layer using the validated DTO
        Auth verifiedUser = authService.verifyOTP(otpRequest);

        ApiResponseConfig<Auth> response = new ApiResponseConfig<>(
                "OTP verified successfully!",
                verifiedUser
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    @Operation(summary = "Resend 2FA OTP to the user's email")
    public ResponseEntity<ApiResponseConfig<Auth>> resendOTP(@RequestBody Map<String, String> request) {
        Auth user = authService.resendOTP(request);

        ApiResponseConfig<Auth> response = new ApiResponseConfig<>(
                "A new OTP has been sent to your email.",
                user
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    @Operation(summary = "Generate a new access token using refresh token")
    public ResponseEntity<ApiResponseConfig<ResponseDto>> refreshToken(
            @Valid @RequestBody RefreshTokenRequestDTO request) {

        // Call the service to refresh tokens
        ResponseDto refreshedTokens = authService.refreshToken(request.getRefreshToken());

        // Wrap the response inside ApiResponseConfig
        ApiResponseConfig<ResponseDto> response = new ApiResponseConfig<>(
                "🎉 New access token generated successfully!",
                refreshedTokens
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/magic-link")
    @Operation(summary = "Send a magic login link to the user's email")
    public ResponseEntity<ApiResponseConfig<String>> sendMagicLink(@Valid @RequestBody MagicLinkRequestDTO request) {

        authService.sendMagicLink(request.email());

        ApiResponseConfig<String> response = new ApiResponseConfig<>(
                "Magic login link sent successfully. Please check your email.",
                null
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/magic-login")
    @Operation(summary = "Login user using a magic login link")
    public ResponseEntity<ApiResponseConfig<ResponseDto>> loginWithMagicLink(
           @Valid @RequestBody MagicLinkTokenDTO request) {
        String token = request.token();
        ResponseDto responseDto = authService.loginWithMagicLink(token);

        ApiResponseConfig<ResponseDto> response = new ApiResponseConfig<>(
                "Login successful via magic link!",
                responseDto
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    @Operation(summary = "Login user with email and password")
    public ResponseEntity<ApiResponseConfig<ResponseDto>> login(@Valid @RequestBody LoginDto loginDto) {
        Auth auth = authService.login(loginDto);

        // Build a safe ResponseDto
        ResponseDto responseDto = new ResponseDto(
                auth.getFirstName(),
                auth.getLastName(),
                auth.getEmail(),
                auth.getIsAccountBlocked(),
                auth.getAccessToken(),
                auth.getRefreshToken(),
                UserRole.valueOf(String.valueOf(auth.getRole()))
        );

        // Wrap in ApiResponseConfig
        ApiResponseConfig<ResponseDto> response = new ApiResponseConfig<>(
                "Login successful!",
                responseDto
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout/{userId}")
    @Operation(summary = "Logout user and invalidate tokens")
    public ResponseEntity<ApiResponseConfig<ResponseDto>> logout(@PathVariable Long userId) {
        ResponseDto responseDto = authService.logout(userId);

        ApiResponseConfig<ResponseDto> response = new ApiResponseConfig<>(
                "Logout successful!",
                responseDto
        );

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/delete/{userId}")
    @Operation(summary = "Delete a user account")
    public ResponseEntity<ApiResponseConfig<ResponseDto>> deleteAccount(@PathVariable Long userId) {
        ResponseDto responseDto = authService.deleteAccount(userId);

        ApiResponseConfig<ResponseDto> response = new ApiResponseConfig<>(
                "Account deleted successfully!",
                responseDto
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset code via email")
    public ResponseEntity<ApiResponseConfig<String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordDTO request,
            HttpServletResponse response
    ) {
        // Service returns the generated reset token
        String resetToken = authService.forgotPassword(request.email());

        // Store token securely in HttpOnly cookie
        Cookie cookie = new Cookie("reset_token", resetToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);       // Only works over HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(15 * 60);    // 15 minutes

        // Add cookie to the response

        response.addCookie(cookie);

        ApiResponseConfig<String> res = new ApiResponseConfig<>(
                "Password reset token sent successfully! Please check your email.",
                null
        );

        return ResponseEntity.ok(res);
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password using HttpOnly reset token")
    public ResponseEntity<ApiResponseConfig<String>> resetPassword(
            @CookieValue(name = "reset_token", required = false) String resetToken,
            @Valid @RequestBody ResetPasswordRequestDTO request
    ) {
        // Only the new password is provided in the body
        authService.resetPassword(request.newPassword(), resetToken);

        ApiResponseConfig<String> response = new ApiResponseConfig<>(
                "Password has been reset successfully!",
                null
        );

        return ResponseEntity.ok(response);
    }


    @GetMapping("/all-users")
    @Operation(summary = "Fetch all registered users")
    public ResponseEntity<ApiResponseConfig<List<Auth>>> findAllUsers() {
        List<Auth> users = authService.findAllUsers();

        ApiResponseConfig<List<Auth>> response = new ApiResponseConfig<>(
                "Fetched all users successfully",
                users
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/fetch-user/{userId}")
    @Operation(summary = "Fetch a user by their ID")
    public ResponseEntity<ApiResponseConfig<Auth>> findUserById(@PathVariable Long userId) {
        Auth user = authService.findUserById(userId);

        ApiResponseConfig<Auth> response = new ApiResponseConfig<>(
                "User fetched successfully",
                user
        );

        return ResponseEntity.ok(response);
    }

    @PatchMapping("/block-account/{userId}")
    @Operation(summary = "Block a user account")
    public ResponseEntity<ApiResponseConfig<Auth>> blockUser(@PathVariable Long userId) {
        Auth blockedUser = authService.blockUser(userId);

        ApiResponseConfig<Auth> response = new ApiResponseConfig<>(
                "User account blocked successfully",
                blockedUser
        );

        return ResponseEntity.ok(response);
    }

    @PatchMapping("/unblock-account/{userId}")
    @Operation(summary = "Unblock a user account")
    public ResponseEntity<ApiResponseConfig<Auth>> unBlockUser(@PathVariable Long userId) {
        Auth unblockedUser = authService.unBlockUser(userId);

        ApiResponseConfig<Auth> response = new ApiResponseConfig<>(
                "User account unblocked successfully",
                unblockedUser
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/google-login")
    @Operation(summary = "Login with Google account using Firebase token")
    public ResponseEntity<ApiResponseConfig<ResponseDto>> loginWithGoogle(
            @RequestBody GoogleLoginRequestDTO request
            ) throws FirebaseAuthException {
        Auth auth = authService.loginWithGoogle(request.googleToken());

        // Wrap the response in ResponseDto without exposing password
        ResponseDto responseDto = new ResponseDto(
                auth.getFirstName(),
                auth.getLastName(),
                auth.getEmail(),
                auth.getIsAccountBlocked(),
                auth.getAccessToken(),
                auth.getRefreshToken(),
                UserRole.valueOf(String.valueOf(auth.getRole()))
        );

        ApiResponseConfig<ResponseDto> response = new ApiResponseConfig<>(
                "Login with Google successful",
                responseDto
        );

        return ResponseEntity.ok(response);
    }

}
