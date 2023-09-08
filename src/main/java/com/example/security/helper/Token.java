package com.example.security.helper;

import com.example.security.entity.User;

import java.time.LocalDateTime;
import java.util.Base64;

public class Token {
    private final static String DELIMITER = ":";

    public static String encodeUser(User user) {
        return Base64.getEncoder().encodeToString((user.getId() + DELIMITER + user.getName() + DELIMITER + LocalDateTime.now().toString()).getBytes());
    }

    public static String[] decode(String token) {
        String str = new String(Base64.getDecoder().decode(token));
        return str.split(DELIMITER, 3);
    }
}
