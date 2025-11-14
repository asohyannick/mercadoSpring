package com.mercado.mercadoSpring.dto.auth;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
public record RegistrationDto(

        @NotBlank(message = "First name cannot be blank")
        @Size(min = 3, max = 15, message = "First name must be between 3 and 15 characters")
        String firstName,

        @NotBlank(message = "Last name cannot be blank")
        @Size(min = 3, max = 15, message = "Last name must be between 3 and 15 characters")
        String lastName,

        @NotBlank(message = "Email cannot be blank")
        @Size(max = 255, message = "Email cannot exceed 255 characters")
        @Email(message = "Email should be valid")
        String email,

        @NotBlank(message = "Password cannot be blank")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
        )
        String password
) {}
