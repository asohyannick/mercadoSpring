package com.mercado.mercadoSpring.service.auth;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.mercado.mercadoSpring.config.JwtUtil;
import com.mercado.mercadoSpring.constants.user.UserRole;
import com.mercado.mercadoSpring.dto.auth.LoginDto;
import com.mercado.mercadoSpring.dto.auth.RegistrationDto;
import com.mercado.mercadoSpring.dto.auth.ResponseDto;
import com.mercado.mercadoSpring.entity.auth.Auth;
import com.mercado.mercadoSpring.mappers.auth.AuthMapper;
import com.mercado.mercadoSpring.repository.auth.AuthRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;
import java.util.UUID;
@Service
@Transactional
public class AuthService {
  private final AuthRepository authRepository;
  private final AuthMapper authMapper;
  private final PasswordEncoder passwordEncoder;
  private final JwtUtil jwtUtil;
  private final JavaMailSender mailSender;

    @Value("${FIREBASE_PRIVATE_KEY}")
    private String firebasePrivateKey;

    @Value("${FIREBASE_CLIENT_EMAIL}")
    private String firebaseClientEmail;

    @Value("${FIREBASE_PROJECT_ID}")
    private String firebaseProjectId;

    public AuthService(
            AuthRepository authRepository,
            AuthMapper authMapper,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            JavaMailSender mailSender
            ) {
        this.authRepository = authRepository;
        this.authMapper = authMapper;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.mailSender = mailSender;
    }

    private String generate2FACode(Auth savedAuth) {
        String otp = String.valueOf(100000 + new Random().nextInt(900000));
        savedAuth.setTwoFactorExpiry(LocalDateTime.now().plusMinutes(5)); // 5 minutes expiry
        savedAuth.setTwoFactorAttempts(0);
        return otp;
    }

    private void send2FACodeEmail(String toEmail, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("Your 2FA Verification Code");
        message.setText(
                """
                        Your verification code is: " +
                        "" + code + 
                        "\nUse this code to verify your account."""
                                .formatted(code)
        );
        mailSender.send(message);
    }

    public ResponseDto register(RegistrationDto registrationDto) {
     if (authRepository.existsByEmail(registrationDto.email())) {
         throw new RuntimeException("Email already exists");
     }
        Auth auth = authMapper.toAuthEntity(registrationDto);
        auth.setPassword(passwordEncoder.encode(registrationDto.password()));
        // Generate 6-digit 2FA code
        String twoFactorCode = generate2FACode(auth);
        auth.setTwoFactorSecret(twoFactorCode);
        auth.setIsTwoFactorVerified(Boolean.valueOf(String.valueOf(false)));

        // Generate access + refresh tokens
        String accessToken = jwtUtil.generateAccessToken(auth.getEmail(), String.valueOf(auth.getRole()));
        String refreshToken = jwtUtil.generateRefreshToken(auth.getEmail());

        auth.setAccessToken(accessToken);
        auth.setRefreshToken(refreshToken);

        Auth savedAuth = authRepository.save(auth);

        // Send 2FA code via email
        send2FACodeEmail(savedAuth.getEmail(), savedAuth.getTwoFactorSecret());

        // Return safe ResponseDTO (without password)
        return new ResponseDto(
                savedAuth.getFirstName(),
                savedAuth.getLastName(),
                savedAuth.getEmail(),
                savedAuth.getIsAccountBlocked(),
                accessToken,
                refreshToken,
                UserRole.valueOf(String.valueOf(savedAuth.getRole()))
        );
    }

    public Auth verifyOTP(Long userId, String otp) {
        Auth auth = authRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!otp.equals(auth.getTwoFactorSecret())) {
            auth.setTwoFactorAttempts(auth.getTwoFactorAttempts() + 1);
            authRepository.save(auth);
            throw new RuntimeException("Invalid OTP");
        }
        if (auth.getTwoFactorExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("OTP has expired. Request a new one.");
        } else {
            auth.setIsTwoFactorVerified(true);
            auth.setTwoFactorSecret(null);
            auth.setTwoFactorExpiry(null);// clear OTP after successful verification
            return authRepository.save(auth);
        }
    }

    public Auth resendOTP(Long userId) {
        Auth auth = authRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if(Boolean.TRUE.equals(auth.getIsTwoFactorVerified())) {
            throw new RuntimeException("2FA already verified");
        }
        if(auth.getTwoFactorAttempts() >= 5) {
            throw new RuntimeException("Maximum OTP attempts reached. Please try again later.");
        }

        if(auth.getTwoFactorExpiry() != null && auth.getTwoFactorExpiry().isAfter(LocalDateTime.now())) {
            throw new RuntimeException("OTP already sent. Please check your email.");
        }
        String newOtp = generate2FACode(auth);
        auth.setTwoFactorSecret(newOtp);
        authRepository.save(auth);
        send2FACodeEmail(auth.getEmail(), newOtp);
        return auth;
    }

    public ResponseDto refreshToken(Long userId, String refreshToken) {
        Auth auth = authRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!refreshToken.equals(auth.getRefreshToken())) {
            throw new RuntimeException("Invalid refresh token");
        }
        try{
            jwtUtil.validateToken(refreshToken);
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Refresh token has expired, Please login again");
        }
        String newAccessToken = jwtUtil.generateAccessToken(auth.getEmail(), String.valueOf(auth.getRole()));
        String newRefreshToken = jwtUtil.generateRefreshToken(auth.getEmail());
        auth.setAccessToken(newAccessToken);
        auth.setRefreshToken(newRefreshToken);
        return new ResponseDto(
                auth.getFirstName(),
                auth.getLastName(),
                auth.getEmail(),
                auth.getIsAccountBlocked(),
                newAccessToken,
                newRefreshToken,
                UserRole.valueOf(String.valueOf(auth.getRole()))
        );
    }

    public void sendMagicLink(String email) {
        Auth auth = authRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        String token = UUID.randomUUID().toString();
        auth.setMagicToken(token);
        auth.setMagicTokenExpiration(LocalDateTime.now().plusMinutes(15)); // 15 minutes expiry
        authRepository.save(auth);
        String magicLink = "http://localhost:3000/magic-login?token=" + token;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your Magic Login Link");
        message.setText("Click the following link to log in: " + magicLink +
                "\n\nThis link will expire in 15 minutes.");
        mailSender.send(message);
    }

    public ResponseDto loginWithMagicLink(String token) {
        Auth auth = authRepository.findByMagicToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));
        if (auth.getMagicTokenExpiration().isBefore(LocalDateTime.now()) || auth.getMagicTokenExpiration() == null) {
            throw new RuntimeException("Token has expired");
        }
        // Invalidate the token after use
        auth.setMagicToken(null);
        auth.setMagicTokenExpiration(null);
        String accessToken = jwtUtil.generateAccessToken(auth.getEmail(), String.valueOf(auth.getRole()));
        String refreshToken = jwtUtil.generateRefreshToken(auth.getEmail());
        auth.setAccessToken(accessToken);
        auth.setRefreshToken(refreshToken);
        authRepository.save(auth);
        return new ResponseDto(
                auth.getFirstName(),
                auth.getLastName(),
                auth.getEmail(),
                auth.getIsAccountBlocked(),
                accessToken,
                refreshToken,
                UserRole.valueOf(String.valueOf(auth.getRole()))
        );
    }

    public Auth login(LoginDto loginDto) {
        Auth auth = authRepository.findByEmail(loginDto.email())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));
        if (auth.getIsAccountBlocked()) {
            throw new RuntimeException("Your account has been blocked. Contact the System Administrator.");
        }

        if (!auth.getIsEmailVerified()) {
            throw new RuntimeException("Email not verified. Please verify your email before logging in.");
        }

        if (!passwordEncoder.matches(loginDto.password(), auth.getPassword())) {
            auth.setFailedLoginAttempts(auth.getFailedLoginAttempts() + 1);
            if (auth.getFailedLoginAttempts() >= 5) {
                auth.setIsAccountBlocked(true);
                authRepository.save(auth);
                throw new RuntimeException("Your account has been blocked due to multiple failed login attempts. Contact the System Administrator.");
            }

            throw  new RuntimeException("Invalid email or password");
        }
        auth.setIsEmailVerified(true);
        auth.setFailedLoginAttempts(0); // Reset on successful login
        // Generate access + refresh tokens
        String accessToken = jwtUtil.generateAccessToken(auth.getEmail(), String.valueOf(auth.getRole()));
        String refreshToken = jwtUtil.generateRefreshToken(auth.getEmail());
        auth.setAccessToken(accessToken);
        auth.setRefreshToken(refreshToken);
        authRepository.save(auth);
        return auth;
    }

    public ResponseDto logout(Long userId) {
      Auth auth = authRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        auth.setAccessToken(null);
        auth.setRefreshToken(null);
        authRepository.save(auth);
        return new ResponseDto(
                auth.getFirstName(),
                auth.getLastName(),
                auth.getEmail(),
                auth.getIsAccountBlocked(),
                null,
                null,
                UserRole.valueOf(String.valueOf(auth.getRole()))
        );
    }

    public ResponseDto deleteAccount(Long userId) {
        Auth auth = authRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        authRepository.delete(auth);
        return new ResponseDto(
                auth.getFirstName(),
                auth.getLastName(),
                auth.getEmail(),
                auth.getIsAccountBlocked(),
                null,
                null,
                UserRole.valueOf(String.valueOf(auth.getRole()))
        );
    }

    public void forgotPassword(String email) {
        Auth auth = authRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        // Generate six digit 2FA code
        String resetCode = generate2FACode(auth);
        auth.setTwoFactorSecret(resetCode);
        auth.setTwoFactorExpiry(LocalDateTime.now().plusMinutes(15)); // 15 minutes expiry
        authRepository.save(auth);
        // Send reset code via email
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Password Reset Verification Code");
        message.setText("Your password reset code is: " + resetCode +
                "\n\nThis code will expire in 15 minutes.");
        mailSender.send(message);
    }

    public void resetPassword(String email, String newPassword, String resetToken) {
        Auth auth = authRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        if (!resetToken.equals(auth.getTwoFactorSecret())) {
            throw new RuntimeException("Invalid reset token");
        }
        if (auth.getTwoFactorExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Reset token has expired");
        } else {
            auth.setPassword(passwordEncoder.encode(newPassword));
            auth.setTwoFactorSecret(null);
            auth.setTwoFactorExpiry(null);
            authRepository.save(auth);
        }
    }

    public List<Auth> findAllUsers() {
        return authRepository.findAll();
    }

    public Auth findUserById(Long userId) {
        return authRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public Auth blockUser(Long userId) {
        Auth auth = authRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        if (Boolean.TRUE.equals(auth.getIsAccountBlocked())) {
            throw new RuntimeException("User account is already blocked");
        }
        auth.setIsAccountBlocked(true);
        return authRepository.save(auth);
    }

    public Auth unBlockUser(Long userId) {
        Auth auth = authRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        if (Boolean.TRUE.equals(auth.getIsAccountBlocked())) {
            throw new RuntimeException("User account is not blocked");
        }
        auth.setIsAccountBlocked(false);
        return authRepository.save(auth);
    }

    // Initialize Firebase with environment variables
    @PostConstruct
    public void init() throws Exception {
        String privateKey = firebasePrivateKey.replace("\\n", "\n"); // replace escaped newlines
        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(
                        com.google.auth.oauth2.GoogleCredentials.fromStream(
                                new ByteArrayInputStream((
                                        "{\n" +
                                                "  \"type\": \"service_account\",\n" +
                                                "  \"project_id\": \"" + firebaseProjectId + "\",\n" +
                                                "  \"private_key_id\": \"ignored\",\n" +
                                                "  \"private_key\": \"" + privateKey + "\",\n" +
                                                "  \"client_email\": \"" + firebaseClientEmail + "\",\n" +
                                                "  \"client_id\": \"ignored\",\n" +
                                                "  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n" +
                                                "  \"token_uri\": \"https://oauth2.googleapis.com/token\",\n" +
                                                "  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n" +
                                                "  \"client_x509_cert_url\": \"ignored\"\n" +
                                                "}").getBytes(StandardCharsets.UTF_8))
                        )
                ).build();

        if (FirebaseApp.getApps().isEmpty()) {
            FirebaseApp.initializeApp(options);
        }
    }

    public Auth loginWithGoogle(String googleToken) throws FirebaseAuthException {
        // Use correct variable name
        FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(googleToken);
        String email = decodedToken.getEmail();

        Auth auth = authRepository.findByEmail(email)
                .orElseGet(() -> createUserFromFirebase(decodedToken));

        String accessToken = jwtUtil.generateAccessToken(auth.getEmail(), String.valueOf(auth.getRole()));
        String refreshToken = jwtUtil.generateRefreshToken(auth.getEmail());
        auth.setAccessToken(accessToken);
        auth.setRefreshToken(refreshToken);

        return authRepository.save(auth);
    }

    private Auth createUserFromFirebase(FirebaseToken token) {
        Auth newUser = new Auth();
        newUser.setEmail(token.getEmail());
        newUser.setFirstName(token.getName() != null ? token.getName().split(" ")[0] : "CUSTOMER");
        newUser.setLastName(token.getName() != null && token.getName().contains(" ") ? token.getName().split(" ")[1] : "CUSTOMER");
        newUser.setIsEmailVerified(token.isEmailVerified());
        newUser.setRole(UserRole.valueOf("CUSTOMER"));
        newUser.setIsAccountBlocked(false);
        return authRepository.save(newUser);
    }
}
