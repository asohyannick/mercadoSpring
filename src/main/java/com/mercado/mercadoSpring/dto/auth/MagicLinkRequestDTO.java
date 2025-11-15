package com.mercado.mercadoSpring.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record MagicLinkRequestDTO(
        @NotBlank(message = "Email must be provided")
        @Email(message = "Invalid email format")
        String email
) {
}
