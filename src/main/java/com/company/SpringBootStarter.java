package com.company;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SpringBootStarter {
    public static void main(String[] args) {
        SpringApplication.run(SpringBootStarter.class, args);
        System.out.println(new BCryptPasswordEncoder(12).encode("admin"));
        System.out.println(new BCryptPasswordEncoder(12).encode("user"));
    }
}
