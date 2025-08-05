package com.sprint.mission.discodeit.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            );

        return http.build();
    }

    @Bean
    public CommandLineRunner printSecurityFilters(FilterChainProxy filterChainProxy) {
        return args -> {
            int index = 1;
            for (SecurityFilterChain chain : filterChainProxy.getFilterChains()) {
                System.out.println("=== Security Filter Chain " + index++ + " ===");
                for (jakarta.servlet.Filter filter : chain.getFilters()) {
                    System.out.println(filter.getClass().getName());
                }
            }
        };
    }
}
