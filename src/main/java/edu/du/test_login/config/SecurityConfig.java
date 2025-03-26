package edu.du.test_login.config;

import edu.du.test_login.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService) {
        this.customOAuth2UserService = customOAuth2UserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // CSRF 보호 비활성화 (필요에 따라 설정)
                .authorizeHttpRequests()  // authorizeRequests() -> authorizeHttpRequests()
                .requestMatchers("/").permitAll() // "/"는 누구나 접근 가능
                .requestMatchers("/login").permitAll() // "/login"은 누구나 접근 가능
                .requestMatchers("/user").hasRole("USER") // "/user"는 USER 권한 가진 사용자만 접근 가능
                .anyRequest().authenticated() // 나머지 요청은 인증된 사용자만 접근 허용
                .and()
                .exceptionHandling().accessDeniedPage("/accessDenied") // 접근 거부 페이지 설정
                .and()
                .logout()
                .logoutUrl("/logout") // 로그아웃 URL
                .logoutSuccessUrl("/") // 로그아웃 성공 후 리디렉션 URL
                .permitAll() // 로그아웃은 모든 사용자에게 허용
                .and()
                .oauth2Login() // OAuth2 로그인 활성화
                .loginPage("/login") // 로그인 페이지 설정
                .userInfoEndpoint() // 사용자 정보 엔드포인트 설정
                .userService(customOAuth2UserService); // 커스텀 OAuth2 사용자 서비스

        return http.build();
    }
}
