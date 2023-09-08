package com.example.security.controller;

import com.example.security.annotation.Authenticated;
import com.example.security.entity.Role;
import com.example.security.entity.User;
import com.example.security.helper.Token;
import com.example.security.helper.UserAndRoleHolder;
import com.example.security.repository.RoleRepository;
import com.example.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

@RestController
@RequestMapping("/user")
public class UserController {
    public static final String HASH_ALGORITHM = "MD5";
    public static final String USER_ALREADY_EXISTS_MSG = "User already exists";
    public static final String USER_DOES_NOT_EXIST_MSG = "User does not exist";
    public static final String WRONG_USERNAME_OR_PASSWORD = "Wrong username or password";
    public static final String INVALID_TOKEN = "Invalid token";
    public static final long TOKEN_VALID_HOURS = 2L;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    @PostMapping
    public void createUser(@RequestBody User user) throws NoSuchAlgorithmException {
        if (isUserExist(user.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, USER_ALREADY_EXISTS_MSG);
        }
        String myHash = encryptString(user.getPassword());
        user.setPassword(myHash);
        userRepository.save(user);
    }

    public static String encryptString(String str) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        md.update(str.getBytes());
        byte[] digest = md.digest();
        return DatatypeConverter.printHexBinary(digest);
    }

    private boolean isUserExist(String name) {
        return userRepository.findByName(name).isPresent();
    }

    @DeleteMapping
    public void deleteUser(@RequestBody User user) {
        if (!isUserExist(user.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, USER_DOES_NOT_EXIST_MSG);
        }
        userRepository.delete(user);
    }

    @PutMapping("/attach")
    public void attachRole(@RequestBody UserAndRoleHolder body) {
        User user = userRepository.findByName(body.getUser().getName()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, USER_DOES_NOT_EXIST_MSG));
        Role role = roleRepository.findByName(body.getRole().getName()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, RoleController.ROLE_DOES_NOT_EXIST_MSG));
        if (!user.getRoles().contains(role)) {
            user.getRoles().add(role);
            userRepository.save(user);
        }
    }

    @PutMapping("/auth")
    public String authenticate(@RequestBody User user) throws NoSuchAlgorithmException {
        User userFromDB = userRepository.findByName(user.getName()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, USER_DOES_NOT_EXIST_MSG));
        if (!encryptString(user.getPassword()).equals(userFromDB.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, WRONG_USERNAME_OR_PASSWORD);
        }
        String token = Token.encodeUser(userFromDB);
        userFromDB.setToken(token);
        userRepository.save(userFromDB);
        return token;
    }

    @PutMapping("/invalidate")
    @Authenticated
    public void invalidateToken(@RequestHeader(name = "AuthToken") String token) {
        String[] tokenParts = Token.decode(token);
        User user = userRepository.findByName(tokenParts[1]).get();
        user.setToken(null);
        userRepository.save(user);
    }

    @GetMapping("/checkRole")
    @Authenticated
    public boolean checkRole(@RequestHeader(name = "AuthToken") String token, @RequestBody Role role) {
        String[] idAndName = Token.decode(token);
        User user = userRepository.findByName(idAndName[1]).get();
        roleRepository.findByName(role.getName()).orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, RoleController.ROLE_DOES_NOT_EXIST_MSG));
        return user.getRoles().contains(role);
    }

    @GetMapping("/roles")
    @Authenticated
    public Set<Role> getAllRoles(@RequestHeader(name = "AuthToken") String token) {
        String[] idAndName = Token.decode(token);
        User user = userRepository.findByName(idAndName[1]).get();
        return user.getRoles();
    }
}
