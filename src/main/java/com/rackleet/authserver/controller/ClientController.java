package com.rackleet.authserver.controller;

import com.rackleet.authserver.dto.request.ClientRegistrationRequest;
import com.rackleet.authserver.dto.response.ClientInfoResponse;
import com.rackleet.authserver.dto.response.ClientRegistrationResponse;
import com.rackleet.authserver.service.ClientService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/clients")
@RequiredArgsConstructor
public class ClientController {

    private final ClientService clientService;

    @PostMapping
    public ResponseEntity<ClientRegistrationResponse> registerClient(
            @Valid @RequestBody ClientRegistrationRequest request) {
        ClientRegistrationResponse response = clientService.registerClient(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<ClientInfoResponse> getClient(@PathVariable String clientId) {
        return ResponseEntity.ok(clientService.getClient(clientId));
    }

    @PutMapping("/{clientId}")
    public ResponseEntity<ClientInfoResponse> updateClient(
            @PathVariable String clientId,
            @RequestBody ClientRegistrationRequest request) {
        return ResponseEntity.ok(clientService.updateClient(clientId, request));
    }

    @DeleteMapping("/{clientId}")
    public ResponseEntity<Void> deactivateClient(@PathVariable String clientId) {
        clientService.deactivateClient(clientId);
        return ResponseEntity.noContent().build();
    }
}