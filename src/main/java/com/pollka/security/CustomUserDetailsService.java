package com.pollka.security;

import com.pollka.model.User;
import com.pollka.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        User user = userRepository
                .findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(()->new UsernameNotFoundException("User with email or username not found: " + usernameOrEmail));
        return UserInfo.create(user);
    }

    @Transactional
    public UserInfo loadUserById(Long id){
        User user = userRepository
                .findById(id)
                .orElseThrow(()->new UsernameNotFoundException("User with id not found: " + id));
        return UserInfo.create(user);
    }
}
