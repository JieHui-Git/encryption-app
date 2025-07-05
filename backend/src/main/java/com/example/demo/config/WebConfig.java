package com.example.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/files/**")  // match your API path
                .allowedOrigins("http://localhost:3000") // React dev server
                .allowedMethods("POST")
                .allowedHeaders("*");
    }
}
