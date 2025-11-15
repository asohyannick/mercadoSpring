package com.mercado.mercadoSpring.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordDTO(
        @NotBlank(message = "Email cannot be blank")
        String email
) { }
