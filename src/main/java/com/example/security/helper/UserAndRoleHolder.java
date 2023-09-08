package com.example.security.helper;

import com.example.security.entity.Role;
import com.example.security.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserAndRoleHolder {
    private User user;
    private Role role;
}
