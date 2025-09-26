package com.seguridad.jwtdemo.controller;

import com.seguridad.jwtdemo.model.LoginRequest;
import com.seguridad.jwtdemo.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class AuthController {
    
    @Autowired
    private JwtUtil jwtUtil;

    // 1. ENDPOINT PÚBLICO: Genera el token si las credenciales son correctas.
    @PostMapping("/auth/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        
        // **SIMULACIÓN** de verificación de credenciales en la base de datos
        if ("admin".equals(request.getUsername()) && "pass".equals(request.getPassword())) {
            
            //  Generar JWT con el Rol "ADMIN"
            String token = jwtUtil.generateToken(request.getUsername(), List.of("ADMIN")); 
            
            // Devolver el token al cliente (Front-end)
            return ResponseEntity.ok("{\"token\": \"" + token + "\"}");
        }
        return ResponseEntity.status(401).body("Credenciales inválidas");
    }

    // 2. ENDPOINT PROTEGIDO: Solo accesible si el token tiene el permiso "ADMIN"
    @GetMapping("/admin/reporte")
    @PreAuthorize("hasAuthority('ADMIN')") // Autorización usando ABAC/RBAC
    public ResponseEntity<String> getAdminReport() {
        return ResponseEntity.ok("Acceso Concedido: Este es el reporte de Administrador Secreto.");
    }
    
    // 3. ENDPOINT PROTEGIDO: Accesible para cualquier usuario autenticado (con token válido)
    @GetMapping("/public/saludo")
    public ResponseEntity<String> getPublicSaludo() {
        return ResponseEntity.ok("Hola, has accedido con un token válido.");
    }
}

