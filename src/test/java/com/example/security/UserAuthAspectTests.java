package com.example.security;

import com.example.security.aspect.UserAuthAspect;
import com.example.security.entity.User;
import com.example.security.helper.Token;
import com.example.security.repository.UserRepository;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@SpringBootTest
class UserAuthAspectTests {
    @MockBean
    private UserRepository userRepository;
    @Autowired
    private UserAuthAspect userAuthAspect;
    @Mock
    private ProceedingJoinPoint proceedingJoinPoint;

    @Test
    void shouldPass() throws Throwable {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        String token = Token.encodeUser(user);
        user.setToken(token);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        when(proceedingJoinPoint.getArgs()).thenReturn(new Object[]{token});
        userAuthAspect.beforeAdvice(proceedingJoinPoint);
        verify(proceedingJoinPoint, times(1)).proceed();
    }

    @Test
    void shouldFailWhenExpired() throws Throwable {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        String token = "MDphZG1pbjoyMDIyLTA5LTA5VDAwOjEzOjQ1Ljc1NTAyNDUwMA=="; //0:admin:2022-09-09T00:13:45.755024500
        user.setToken(token);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        when(proceedingJoinPoint.getArgs()).thenReturn(new Object[]{token});
        assertThrows(ResponseStatusException.class, () -> userAuthAspect.beforeAdvice(proceedingJoinPoint));
        verify(proceedingJoinPoint, never()).proceed();
    }

    @Test
    void shouldFailWhenWrongFormat() throws Throwable {
        User user = new User("admin", "admin", new HashSet<>());
        user.setId(1L);
        String token = "YWRtaW46MjAyMi0wOS0wOVQwMDoxMzo0NS43NTUwMjQ1MDA="; //admin:2022-09-09T00:13:45.755024500
        user.setToken(token);
        when(userRepository.findByName(user.getName())).thenReturn(Optional.of(user));
        when(proceedingJoinPoint.getArgs()).thenReturn(new Object[]{token});
        assertThrows(ResponseStatusException.class, () -> userAuthAspect.beforeAdvice(proceedingJoinPoint));
        verify(proceedingJoinPoint, never()).proceed();
    }
}
