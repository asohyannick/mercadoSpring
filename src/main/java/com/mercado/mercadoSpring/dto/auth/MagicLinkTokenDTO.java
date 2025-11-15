package com.mercado.mercadoSpring.dto.auth;
import jakarta.validation.constraints.NotBlank;
public record MagicLinkTokenDTO(
        @NotBlank(message = "Token must be provided")
        String token
) {
}
