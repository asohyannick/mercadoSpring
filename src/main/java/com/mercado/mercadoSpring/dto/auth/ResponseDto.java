package com.mercado.mercadoSpring.dto.auth;

import com.mercado.mercadoSpring.constants.user.UserRole;

public record ResponseDto(
        String firstName,
        String lastName,
        String email,
        Boolean isAccountBlocked,
        String accessToken,
        String refreshToken,
        UserRole role
) {}
