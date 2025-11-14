package com.mercado.mercadoSpring.repository.auth;
import com.mercado.mercadoSpring.constants.user.UserRole;
import com.mercado.mercadoSpring.entity.auth.Auth;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface AuthRepository extends JpaRepository<Auth, Long> {
    List<Auth> findByRole(UserRole role);

    Optional<Auth> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<Auth> findByMagicToken(String magicToken);
}
