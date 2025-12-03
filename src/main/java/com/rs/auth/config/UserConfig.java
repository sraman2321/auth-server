package com.rs.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;

@Configuration
public class UserConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public UserDetailsService users(DataSource dataSource, PasswordEncoder passwordEncoder) {
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);


        if (!users.userExists("alice")) {
            users.createUser(User.withUsername("alice")
                    .password(passwordEncoder.encode("password"))
                    .roles("USER")
                    .build());
        }
        if (!users.userExists("admin")) {
            users.createUser(User.withUsername("admin")
                    .password(passwordEncoder.encode("adminpass"))
                    .roles("ADMIN")
                    .build());
        }


        return users;
    }
}
