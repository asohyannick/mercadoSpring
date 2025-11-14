package com.mercado.mercadoSpring.controller.product;
import com.mercado.mercadoSpring.config.ApiResponseConfig;
import com.mercado.mercadoSpring.dto.product.ProductDto;
import com.mercado.mercadoSpring.entity.product.Product;
import com.mercado.mercadoSpring.mappers.product.ProductMapper;
import com.mercado.mercadoSpring.repository.product.ProductRepository;
import com.mercado.mercadoSpring.service.product.ProductService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/${API_VERSION}/product")
@RequiredArgsConstructor
@Tag(name = "Product Management Endpoints", description = "APIs for managing products")
public class ProductController {
    private final ProductService productService;
    private final ProductRepository productRepository;
    private final ProductMapper productMapper;

    // Create a new product
    @PostMapping("/create-product")
    @Operation(summary = "Create a new product", description = "Creates a new product in the system")
    public ResponseEntity<ApiResponseConfig<ProductDto>> createProduct(@Valid @RequestBody ProductDto productDto) {
        Product product = productMapper.toEntity(productDto);
        Product savedProduct = productRepository.save(product);
        ProductDto savedProductDto = productMapper.toDto(savedProduct);
        ApiResponseConfig<ProductDto> response = new ApiResponseConfig<>(
                "🎉 Product created successfully",
                savedProductDto
        );
        return ResponseEntity.ok(response);
    }

    @GetMapping("/all-products")
    @Operation(summary = "Get all products", description = "Retrieves a list of all products")
    public ResponseEntity<ApiResponseConfig<List<ProductDto>>> getAllProducts() {
        List<Product> products = productService.getAllProducts();
        List<ProductDto> productDtos = products.stream()
                .map(productMapper::toDto)
                .toList();

        ApiResponseConfig<List<ProductDto>> response = new ApiResponseConfig<>(
                "Fetched all products successfully 🎉",
                productDtos
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/single-product/{id}")
    @Operation(summary = "Get product by ID", description = "Retrieves a product by its ID")
    public ResponseEntity<ApiResponseConfig<ProductDto>> getProductById(@PathVariable Long id) {
        Product product = productService.getProductById(id);
        ProductDto productDto = productMapper.toDto(product);

        ApiResponseConfig<ProductDto> response = new ApiResponseConfig<>(
                "Product retrieved successfully ✅",
                productDto
        );

        return ResponseEntity.ok(response);
    }


    @PutMapping("/update-product/{id}")
    @Operation(summary = "Update product", description = "Update an existing product by its ID")
    public ResponseEntity<ApiResponseConfig<ProductDto>> updateProduct(
            @PathVariable Long id,
            @Valid @RequestBody ProductDto productDto
    ) {
        Product product = productMapper.toEntity(productDto);
        product.setId(id);

        Product updatedProduct = productService.updateProduct(id, product);
        ProductDto updatedProductDto = productMapper.toDto(updatedProduct);

        ApiResponseConfig<ProductDto> response = new ApiResponseConfig<>(
                "Product updated successfully 🔄",
                updatedProductDto
        );

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/delete-product/{id}")
    @Operation(summary = "Delete product", description = "Deletes a product by its ID")
    public ResponseEntity<ApiResponseConfig<ProductDto>> deleteProduct(@PathVariable Long id) {

        // 1️⃣ Fetch product before deletion
        Product product = productService.getProductById(id);
        ProductDto deletedProductDto = productMapper.toDto(product);

        // 2️⃣ Delete the product
        productService.deleteProduct(id);

        // 3️⃣ Return deleted product with a success message
        ApiResponseConfig<ProductDto> response = new ApiResponseConfig<>(
                "Product deleted successfully 🗑️",
                deletedProductDto
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/search-products")
    @Operation(summary = "Search products", description = "Search for products based on various criteria")
    public ResponseEntity<ApiResponseConfig<List<ProductDto>>> searchProducts(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String brand,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Double minPrice,
            @RequestParam(required = false) Double maxPrice,
            @RequestParam(required = false) Boolean isAvailable,
            @RequestParam(required = false) Double minRating,
            @RequestParam(required = false) Double maxRating
    ) {
        List<Product> products = productService.searchProducts(
                keyword, brand, category, minPrice, maxPrice, isAvailable, minRating, maxRating
        );

        List<ProductDto> productDtos = products.stream()
                .map(productMapper::toDto)
                .toList();

        ApiResponseConfig<List<ProductDto>> response = new ApiResponseConfig<>(
                "Product search completed successfully 🔍",
                productDtos
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/available/{category}")
    @Operation(summary = "Get products by category", description = "Retrieves products belonging to a specific category")
    public ResponseEntity<ApiResponseConfig<List<ProductDto>>> getAllProductsByCategory(
            @PathVariable String category
    ) {
        List<Product> products = productService.getProductsByCategory(category);
        List<ProductDto> productDtos = products.stream()
                .map(productMapper::toDto)
                .toList();

        ApiResponseConfig<List<ProductDto>> response = new ApiResponseConfig<>(
                "Products fetched successfully by category 📦",
                productDtos
        );

        return ResponseEntity.ok(response);
    }


    @GetMapping("/available-by-description/{description}")
    @Operation(summary = "Get products by description", description = "Retrieves products matching a specific description")
    public ResponseEntity<ApiResponseConfig<List<ProductDto>>> getProductsByDescription(
            @PathVariable String description
    ) {
        List<Product> products = productService.findProductsByDescription(description);
        List<ProductDto> productDtos = products.stream()
                .map(productMapper::toDto)
                .toList();

        ApiResponseConfig<List<ProductDto>> response = new ApiResponseConfig<>(
                "Products fetched by description successfully 📝",
                productDtos
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/search")
    @Operation(summary = "Get products by category and description", description = "Retrieves products matching both category and description")
    public ResponseEntity<ApiResponseConfig<List<ProductDto>>> getProductsByCategoryAndDescription(
            @RequestParam String category,
            @RequestParam String description
    ) {
        List<Product> products = productService.getProductsByCategoryAndDescription(category, description);
        List<ProductDto> productDtos = products.stream()
                .map(productMapper::toDto)
                .toList();

        ApiResponseConfig<List<ProductDto>> response = new ApiResponseConfig<>(
                "Products fetched by both category and description 🎯",
                productDtos
        );

        return ResponseEntity.ok(response);
    }

}