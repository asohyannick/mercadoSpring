package com.mercado.mercadoSpring.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record GoogleLoginRequestDTO(
        @NotBlank(message = "Google token cannot be blank")
        String googleToken
) {}
