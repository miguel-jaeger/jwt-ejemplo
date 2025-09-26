package com.seguridad.jwtdemo.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {
    // CLAVE SECRETA: Generada automáticamente para esta demostración.
    private final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Generar Token: Crea el token, lo firma y le pone una fecha de expiración
    // corta (30 min).
    public String generateToken(String username, List<String> roles) {
        return Jwts.builder()
                .setSubject(username) // El "sujeto" del token (el usuario)
                .claim("roles", roles) // Añade los roles al Payload (Body)
                .setIssuedAt(new Date(System.currentTimeMillis())) // Fecha de emisión
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // Expira en 30 minutos
                .signWith(SECRET_KEY) // 🔑 Firma el token con la Clave Secreta
                .compact();
    }

    // Validar Token: Verifica que la firma sea correcta y que no haya expirado.
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).build().parseClaimsJws(token);
            return true; // Si llega aquí, el token es válido
        } catch (Exception e) {
            return false; // Token inválido o expirado
        }
    }

    // Obtener Username (para cargarlo en Spring Security)
    public String getUsernameFromToken(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // Obtener Roles
    public List<String> getRolesFromToken(String token) {
        return (List<String>) Jwts.parser().setSigningKey(SECRET_KEY).build()
                .parseClaimsJws(token)
                .getBody()
                .get("roles");
    }
}
