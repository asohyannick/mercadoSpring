package com.mercado.mercadoSpring.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequestDTO(
        @NotBlank(message = "New password must be provided")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        String newPassword
) {}
