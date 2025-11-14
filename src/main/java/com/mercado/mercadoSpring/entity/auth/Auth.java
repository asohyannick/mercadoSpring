package com.mercado.mercadoSpring.entity.auth;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.mercado.mercadoSpring.constants.user.UserRole;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Auth {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Column(nullable = false, unique = true)
    private String email;

    @JsonIgnore
    @Column(nullable = false)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role = UserRole.CUSTOMER;

    @Column(nullable = false)
    private Boolean isAccountBlocked = false;

    @Column(nullable = true)
    private Boolean isEmailVerified = false;

    @Column(nullable = true)
    private String refreshToken;

    @Column(nullable = true)
    private String accessToken;

    @Column(nullable = true)
    private String twoFactorSecret;

    @Column(nullable = true)
    private Boolean isTwoFactorVerified = false;

    @Column
    private LocalDateTime twoFactorExpiry;

    @Column
    private Integer twoFactorAttempts = 0;

    @Column
    private Integer failedLoginAttempts = 0;
    @Column
    private String magicToken;

    @Column
    private LocalDateTime magicTokenExpiration;

}
