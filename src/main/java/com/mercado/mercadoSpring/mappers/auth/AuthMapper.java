package com.mercado.mercadoSpring.mappers.auth;

import com.mercado.mercadoSpring.dto.auth.IsEmailVerifiedDto;
import com.mercado.mercadoSpring.dto.auth.RegistrationDto;
import com.mercado.mercadoSpring.dto.auth.ResponseDto;
import com.mercado.mercadoSpring.entity.auth.Auth;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(
        componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.SET_TO_DEFAULT
)
public interface AuthMapper {

    RegistrationDto toRegistrationDto(Auth auth);

    Auth toAuthEntity(RegistrationDto registrationDto);

    @Mapping(source = "isAccountBlocked", target = "isAccountBlocked")
    ResponseDto toResponseDto(Auth auth);

    @Mapping(source = "isEmailVerified", target = "isEmailVerified")

    IsEmailVerifiedDto toIsEmailVerifiedDto(Auth auth);
}
