package com.seguridad.jwtdemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // Permite usar @PreAuthorize
public class SecurityConfig {

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 1. Deshabilitar CSRF (necesario para APIs REST Stateless)
            .csrf(AbstractHttpConfigurer::disable)
            
            // 2. Definir las reglas de Autorización (Quién accede a dónde)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login").permitAll() // Permitir acceso libre al login
                .requestMatchers("/api/public/saludo").permitAll() // Permitir acceso libre al login
                .requestMatchers("/api/admin/**").hasAuthority("ADMIN") // Proteger por permiso/rol
                .anyRequest().authenticated() // Cualquier otra URL requiere autenticación (token)
            )
            
            // 3. CRUCIAL: Configurar el sistema como Stateless (sin sesiones)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // 4. Añadir nuestro filtro JWT ANTES del filtro de autenticación estándar de Spring
            .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
            
        return http.build();
    }
}
