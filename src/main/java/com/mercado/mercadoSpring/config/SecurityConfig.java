package com.mercado.mercadoSpring.config;
import com.mercado.mercadoSpring.constants.user.UserRole;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
@Configuration
public class SecurityConfig {
    @Value("${API_VERSION}")
    private String apiVersion;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        String apiBase = "/api/" + apiVersion;
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth

                        // ---------- Public routes ----------
                        .requestMatchers(
                                apiBase + "/auth/register",
                                apiBase + "/auth/login",
                                apiBase + "/auth/forgot-password",
                                apiBase + "/auth/reset-password",
                                apiBase + "/auth/magic-link",
                                apiBase + "/auth/magic-login",
                                apiBase + "/auth/verify-otp",
                                apiBase + "/auth/resend-otp",
                                apiBase + "/auth/google-login",
                                apiBase + "/products/search-products",
                                apiBase + "/products/available/**",
                                apiBase + "/products/search",
                                apiBase + "/products/filter",
                                apiBase + "/products/available-by-description/**"
                        ).permitAll()

                        // ---------- CLIENT routes ----------
                        .requestMatchers(
                                apiBase + "/products/{id}",
                                apiBase + "/auth/logout/**"
                        ).hasAnyRole(
                                UserRole.CUSTOMER.name(),
                                UserRole.DEVOPS.name(),
                                UserRole.SELLER.name(),
                                UserRole.ADMIN.name(),
                                UserRole.DEVELOPER.name()
                        )

                        // ---------- SELLER routes ----------
                        .requestMatchers(
                                apiBase + "/products/create-product",
                                apiBase + "/products/update-product/{id}",
                                apiBase + "/products/delete-product/{id}",
                                apiBase + "/products/all-products",
                                apiBase + "/products/single-product/{id}"
                        ).hasAnyRole(
                                UserRole.SELLER.name(),
                                UserRole.ADMIN.name(),
                                UserRole.DEVOPS.name()
                        )

                        // ---------- ADMIN routes ----------
                        .requestMatchers(
                                apiBase + "/auth/all-users",
                                apiBase + "/auth/fetch-user/{userId}",
                                apiBase + "/auth/delete/{userId}",
                                apiBase + "/auth/block-account/{userId}",
                                apiBase + "/auth/unblock-account/{userId}",
                                apiBase + "/auth/refresh-token",
                                apiBase + "/products/create-product",
                                apiBase + "/products/update-product/{id}",
                                apiBase + "/products/delete-product/{id}",
                                apiBase + "/products/all-products",
                                apiBase + "/products/single-product/{id}"
                        ).hasAnyRole(
                                UserRole.ADMIN.name(),
                                UserRole.DEVOPS.name()
                        )

                        // ---------- Any other request must be authenticated ----------
                        .anyRequest().authenticated()
                );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

