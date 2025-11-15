package com.mercado.mercadoSpring.entity.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.mercado.mercadoSpring.constants.user.UserRole;
import jakarta.persistence.*;
import lombok.*;
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

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role = UserRole.CUSTOMER;

    @Builder.Default
    @Column(nullable = false)
    private Boolean isAccountBlocked = false;

    @Builder.Default
    @Column(nullable = false)
    private Boolean isEmailVerified = false;

    @Column
    private String refreshToken;

    @Column
    private String accessToken;

    @Column
    private String twoFactorSecret;

    @Builder.Default
    @Column(nullable = false)
    private Boolean isTwoFactorVerified = false;

    @Column
    private LocalDateTime twoFactorExpiry;

    @Builder.Default
    @Column(nullable = false)
    private Integer twoFactorAttempts = 0;

    @Builder.Default
    @Column(nullable = false)
    private Integer failedLoginAttempts = 0;

    @Column
    private String magicToken;

    @Column
    private LocalDateTime magicTokenExpiration;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

}
