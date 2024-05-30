package com.doit.CRUD.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
	        httpSecurity.cors(cors -> cors.configurationSource(request -> {
	            CorsConfiguration corsConfiguration = new CorsConfiguration();
	            corsConfiguration.setAllowedOrigins(Arrays.asList(""));
	            corsConfiguration.setAllowedMethods(Arrays.asList(""));
	            corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
	            return corsConfiguration;
	        })).csrf(csrf -> csrf.disable()).authorizeHttpRequests(aut -> aut.anyRequest().permitAll());

	        return httpSecurity.build();
	    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();
        UserDetails admin = User.withUsername("admin")
            .password(passwordEncoder().encode("admin"))
            .roles("ADMIN")
            .build();
        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
