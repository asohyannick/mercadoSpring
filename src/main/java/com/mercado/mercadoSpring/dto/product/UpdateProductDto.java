package com.mercado.mercadoSpring.dto.product;

import jakarta.validation.constraints.*;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Data Transfer Object for updating a Product")
public record UpdateProductDto(
        @Schema(description = "Unique identifier of the product", example = "1")
        Long id,

        @NotBlank(message = "Image URL cannot be blank")
        @Schema(description = "URL of the product image", example = "http://example.com/image.jpg")
        String imageURL,

        @NotBlank(message = "Name is required")
        @Size(max = 100, message = "Name cannot exceed 100 characters")
        @Schema(description = "Name of the product", example = "Wireless Mouse")
        String name,

        @NotBlank(message = "Description is required")
        @Size(max = 2000, message = "Description cannot exceed 2000 characters")
        @Schema(description = "Detailed description of the product", example = "A high-quality wireless mouse with ergonomic design.")
        String description,

        @Positive(message = "Price must be a positive value")
        @Schema(description = "Price of the product", example = "29.99")
        Double price,

        @NotBlank(message = "Category is required")
        @Size(max = 50, message = "Category cannot exceed 50 characters")
        @Schema(description = "Category of the product", example = "Electronics")
        String category,

        @NotBlank(message = "Brand is required")
        @Size(max = 50, message = "Brand cannot exceed 50 characters")
        @Schema(description = "Brand of the product", example = "Logitech")
        String brand,

        @PositiveOrZero(message = "Stock quantity cannot be negative")
        @Schema(description = "Available stock quantity of the product", example = "150")
        Integer stockQuantity,

        @NotNull(message = "Availability status is required")
        @Schema(description = "Availability status of the product", example = "true")
        Boolean available,

        @DecimalMin(value = "0.0", message = "Rating cannot be less than 0")
        @DecimalMax(value = "5.0", message = "Rating cannot exceed 5")
        @Schema(description = "Average rating of the product", example = "4.5")
        Double rating,

        @PositiveOrZero(message = "Number of reviews cannot be negative")
        @Schema(description = "Total number of reviews for the product", example = "250")
        Integer numberOfReviews,

        @NotBlank(message = "Country of origin is required")
        @Size(max = 100, message = "Country of origin cannot exceed 100 characters")
        @Schema(description = "Country where the product was manufactured", example = "USA")
        String countryOfOrigin,

        @NotBlank(message = "City is required")
        @Size(max = 100, message = "City cannot exceed 100 characters")
        @Schema(description = "City where the product was manufactured", example = "San Francisco")
        String city,

        @NotBlank(message = "State is required")
        @Size(max = 100, message = "State cannot exceed 100 characters")
        @Schema(description = "State where the product was manufactured", example = "California")
        String state,

        @NotBlank(message = "Zip code is required")
        @Size(max = 20, message = "Zip code cannot exceed 20 characters")
        @Schema(description = "Zip code of the manufacturing location", example = "94107")
        String zipCode
) {
    // Optional: canonical constructor to assign default values if needed
    public UpdateProductDto {
        if (available == null) available = true;
        if (rating == null) rating = 0.0;
        if (numberOfReviews == null) numberOfReviews = 0;
    }
}
