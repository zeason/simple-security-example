package com.example.security.controller;

import com.example.security.entity.Role;
import com.example.security.repository.RoleRepository;
import com.example.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/role")
public class RoleController {
    public static final String HASH_ALGORITHM = "MD5";
    public static final String ROLE_ALREADY_EXISTS_MSG = "Role already exists";
    public static final String ROLE_DOES_NOT_EXIST_MSG = "Role does not exist";
    private RoleRepository roleRepository;
    private UserRepository userRepository;

    @Autowired
    public RoleController(RoleRepository roleRepository, UserRepository userRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @PostMapping
    public void createRole(@RequestBody Role role) {
        if (isRoleExist(role.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ROLE_ALREADY_EXISTS_MSG);
        }
        roleRepository.save(role);
    }

    private boolean isRoleExist(String name) {
        return roleRepository.findByName(name).isPresent();
    }

    @DeleteMapping
    public void deleteRole(@RequestBody Role role) {
        if (!isRoleExist(role.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ROLE_DOES_NOT_EXIST_MSG);
        }
        userRepository.findAll().forEach(user -> user.getRoles().remove(role));
        roleRepository.delete(role);
    }
}
