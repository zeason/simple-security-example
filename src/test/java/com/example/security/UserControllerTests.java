package com.example.security;

import com.example.security.aspect.UserAuthAspect;
import com.example.security.controller.RoleController;
import com.example.security.controller.UserController;
import com.example.security.entity.Role;
import com.example.security.entity.User;
import com.example.security.helper.Token;
import com.example.security.helper.UserAndRoleHolder;
import com.example.security.repository.RoleRepository;
import com.example.security.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTests {
    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private UserRepository userRepository;
    @MockBean
    private RoleRepository roleRepository;
    @Autowired
    private ApplicationContext applicationContext;

    private ObjectMapper mapper = new ObjectMapper();

    @Test
    void shouldCreateNewUser() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        when(userRepository.findByName(user.getName())).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenReturn(user);
        this.mockMvc.perform(MockMvcRequestBuilders.post("/user").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(user)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldFailCreatingDuplicateUser() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        this.mockMvc.perform(MockMvcRequestBuilders.post("/user").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(user)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldDeleteUser() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        this.mockMvc.perform(MockMvcRequestBuilders.delete("/user").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(user)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldFailDeleteNonExistUser() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.empty());
        this.mockMvc.perform(MockMvcRequestBuilders.delete("/user").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(user)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldAttachRoleToUser() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        Role role = new Role(1L, "admin");
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.of(role));
        UserAndRoleHolder userAndRoleHolder = new UserAndRoleHolder(user, role);
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/attach").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(userAndRoleHolder)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldDoNothingAttachRoleToUser() throws Exception {
        Role role = new Role(1L, "admin");
        User user = new User("admin", "admin", Set.of(role));
        user.setId(1L);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.of(role));
        UserAndRoleHolder userAndRoleHolder = new UserAndRoleHolder(user, role);
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/attach").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(userAndRoleHolder)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldFailAttachRoleToUserWhenUserNotExist() throws Exception {
        Role role = new Role(1L, "admin");
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.empty());
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.of(role));
        UserAndRoleHolder userAndRoleHolder = new UserAndRoleHolder(user, role);
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/attach").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(userAndRoleHolder)))
                .andExpect(status().isBadRequest())
                .andDo(print());
    }

    @Test
    void shouldFailAttachRoleToUserWhenRoleNotExist() throws Exception {
        Role role = new Role(1L, "admin");
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.empty());
        UserAndRoleHolder userAndRoleHolder = new UserAndRoleHolder(user, role);
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/attach").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(userAndRoleHolder)))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertEquals(RoleController.ROLE_DOES_NOT_EXIST_MSG, result.getResponse().getErrorMessage()))
                .andDo(print());
    }

    @Test
    void shouldAuthenticateUser() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        User userFromDB = new User("admin", UserController.encryptString("admin"), new HashSet<>());
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(userFromDB));
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/auth").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(user)))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    void shouldFailAuthenticateNonExistUser() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.empty());
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/auth").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(user)))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertEquals(UserController.USER_DOES_NOT_EXIST_MSG, result.getResponse().getErrorMessage()))
                .andDo(print());
    }

    @Test
    void shouldFailAuthenticateUserWithWrongPassword() throws Exception {
        User user = new User("admin", "123456", new HashSet<>());
        user.setId(1L);
        User userFromDB = new User("admin", UserController.encryptString("admin"), new HashSet<>());
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(userFromDB));
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/auth").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(user)))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertEquals(UserController.WRONG_USERNAME_OR_PASSWORD, result.getResponse().getErrorMessage()))
                .andDo(print());
    }

    @Test
    void shouldInvalidateToken() throws Exception {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        User userFromDB = new User("admin", UserController.encryptString("admin"), new HashSet<>());
        String token = Token.encodeUser(user);
        userFromDB.setToken(token);
        applicationContext.getBean(UserAuthAspect.class).setUserRepository(userRepository);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(userFromDB));
        this.mockMvc.perform(MockMvcRequestBuilders.put("/user/invalidate").header("AuthToken", token))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    void shouldReturnRoleAttachedToUser() throws Exception {
        Role role = new Role(1L, "admin");
        User user = new User("admin", "admin", Set.of(role));
        user.setId(1L);
        String token = Token.encodeUser(user);
        user.setToken(token);
        applicationContext.getBean(UserAuthAspect.class).setUserRepository(userRepository);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.of(role));
        this.mockMvc.perform(MockMvcRequestBuilders.get("/user/checkRole").header("AuthToken", token).contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(role)))
                .andExpect(status().isOk())
                .andExpect(content().string("true"))
                .andDo(print());
    }

    @Test
    void shouldReturnAllRolesAttachedToUser() throws Exception {
        Role role1 = new Role(1L, "admin");
        Role role2 = new Role(2L, "reader");
        User user = new User("admin", "admin", Set.of(role1, role2));
        user.setId(1L);
        String token = Token.encodeUser(user);
        user.setToken(token);
        applicationContext.getBean(UserAuthAspect.class).setUserRepository(userRepository);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        this.mockMvc.perform(MockMvcRequestBuilders.get("/user/roles").header("AuthToken", token))
                .andExpect(status().isOk())
                .andDo(print());
    }
}
