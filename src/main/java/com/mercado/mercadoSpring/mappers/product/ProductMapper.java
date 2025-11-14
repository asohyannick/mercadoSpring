package com.mercado.mercadoSpring.mappers.product;
import com.mercado.mercadoSpring.dto.product.ProductDto;
import com.mercado.mercadoSpring.entity.product.Product;
import org.mapstruct.Mapper;
import org.mapstruct.NullValuePropertyMappingStrategy;
@Mapper(
        componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.SET_TO_DEFAULT
)
public interface ProductMapper {

    ProductDto toDto(Product product);

    Product toEntity(ProductDto productDto);
}
