package com.example.security;

import com.example.security.entity.Role;
import com.example.security.repository.RoleRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RoleControllerTests {
    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private RoleRepository roleRepository;

    private ObjectMapper mapper = new ObjectMapper();

    @Test
    void shouldCreateNewRole() throws Exception {
        Role role = new Role();
        role.setName("admin");
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.empty());
        when(roleRepository.save(any(Role.class))).thenReturn(role);
        this.mockMvc.perform(MockMvcRequestBuilders.post("/role").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(role)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldFailCreatingDuplicateRole() throws Exception {
        Role role = new Role();
        role.setName("admin");
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.of(role));
        this.mockMvc.perform(MockMvcRequestBuilders.post("/role").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(role)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldDeleteRole() throws Exception {
        Role role = new Role();
        role.setId(1L);
        role.setName("admin");
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.of(role));
        this.mockMvc.perform(MockMvcRequestBuilders.delete("/role").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(role)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldFailDeleteNonExistRole() throws Exception {
        Role role = new Role();
        role.setId(1L);
        role.setName("admin");
        when(roleRepository.findByName(role.getName())).thenReturn(Optional.empty());
        this.mockMvc.perform(MockMvcRequestBuilders.delete("/role").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(role)))
                .andExpect(status().isBadRequest());
    }
}
