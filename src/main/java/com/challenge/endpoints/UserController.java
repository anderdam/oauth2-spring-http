package com.challenge.endpoints;

import com.challenge.entity.User;
import com.challenge.service.impl.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@AllArgsConstructor
public class UserController {

    private final UserService service;

    @GetMapping("/user/{id}")
    @PreAuthorize("hasRole('SCOPE_read')")
    public User findById(@PathVariable Long id) {
        return service.findById(id).orElse(null);
    }

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public List<User> findAll(@RequestParam(required = false) Optional<String> accelerationName,
                              @RequestParam(required = false) Optional<Long> companyId) {
        return accelerationName.map(service::findByAccelerationName)
                .orElseGet(() -> companyId.map(service::findByCompanyId).orElse(new ArrayList<>()));
    }
}
