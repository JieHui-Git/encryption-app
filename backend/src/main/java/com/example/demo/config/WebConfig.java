package com.example.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/files/**")  // match your API path
                .allowedOrigins("http://localhost:3000", "http://3.107.86.220:3000") // allow local dev and deployed
                .allowedMethods("POST")
                .allowedHeaders("*");
    }
}
