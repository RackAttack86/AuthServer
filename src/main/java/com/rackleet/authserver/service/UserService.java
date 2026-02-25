package com.rackleet.authserver.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.rackleet.authserver.dto.request.UserRegistrationRequest;
import com.rackleet.authserver.dto.response.UserResponse;
import com.rackleet.authserver.exception.OAuthError;
import com.rackleet.authserver.exception.OAuthException;
import com.rackleet.authserver.repository.UserRepository;
import com.rackleet.authserver.entity.User;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserResponse registerUser(UserRegistrationRequest request) {
        
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Username already registered: " + request.getUsername(), HttpStatus.CONFLICT);
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Email already registered: " + request.getEmail(), HttpStatus.CONFLICT);
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());

        /**
         * Bcrypt with cost factor 12 - set in SecurityConfig
         * Cost 12 means 2^12 = 4096 hashing rounds
         * High enough to resist brute force, low enough to not make registration feel slow (~250ms)
         */
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);
        return buildResponse(user);
    }

    public User authenticateUser(String username, String password) {
        
        User user = userRepository.findByUsername(username)
                .filter(User::isActive)
                .orElseThrow(() -> new OAuthException(OAuthError.ACCESS_DENIED, "Invalid username or password", HttpStatus.UNAUTHORIZED));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new OAuthException(OAuthError.ACCESS_DENIED, "Invalid username or password", HttpStatus.UNAUTHORIZED);
        }

        return user;
    }

    private UserResponse buildResponse(User user) {
        
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setEmail(user.getEmail());
        response.setEmailVerified(user.isEmailVerified());
        response.setCreatedAt(user.getCreatedAt());
        return response;
    }
}
