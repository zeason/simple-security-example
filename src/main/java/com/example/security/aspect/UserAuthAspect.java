package com.example.security.aspect;

import com.example.security.controller.UserController;
import com.example.security.entity.User;
import com.example.security.helper.Token;
import com.example.security.repository.UserRepository;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;

@Aspect
@Component
public class UserAuthAspect {
    private UserRepository userRepository;

    @Autowired
    public UserAuthAspect(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Around("@annotation(com.example.security.annotation.Authenticated)")
    public Object beforeAdvice(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        String token = args[0].toString();
        String[] decoded = Token.decode(token);
        Optional<User> user = userRepository.findByName(decoded[1]);
        if (user.isPresent() && token.equals(user.get().getToken())) {
            LocalDateTime issued = LocalDateTime.parse(decoded[2]);
            if (issued.plusHours(UserController.TOKEN_VALID_HOURS).compareTo(LocalDateTime.now()) >= 0) {
                return joinPoint.proceed();
            }
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }
}
