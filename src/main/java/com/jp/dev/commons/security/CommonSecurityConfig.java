package com.jp.dev.commons.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class CommonSecurityConfig {

  private final AuthenticationManager authenticationManager;

  public CommonSecurityConfig(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/h2-console/**").permitAll()
            .anyRequest().authenticated())
        .addFilter(new JWTAuthorizationFilter(authenticationManager))
        .sessionManagement(smc -> smc
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http.headers(hd -> hd.frameOptions(FrameOptionsConfig::disable));
    return http.build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

    CorsConfiguration corsConfiguration = new CorsConfiguration().applyPermitDefaultValues();
    corsConfiguration.addAllowedMethod(HttpMethod.DELETE);
    corsConfiguration.addAllowedMethod(HttpMethod.OPTIONS);
    corsConfiguration.addAllowedMethod(HttpMethod.PATCH);
    corsConfiguration.addAllowedMethod(HttpMethod.PUT);
    source.registerCorsConfiguration("/**", corsConfiguration);

    return source;
  }
}