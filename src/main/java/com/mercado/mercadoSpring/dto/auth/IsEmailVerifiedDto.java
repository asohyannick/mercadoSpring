package com.mercado.mercadoSpring.dto.auth;

import jakarta.validation.constraints.NotNull;

public record IsEmailVerifiedDto(
        @NotNull(message = "Email verification status is required")
        Boolean isEmailVerified
) {}
