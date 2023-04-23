package com.example.security1.config;

import com.example.security1.config.oauth.PrincipalOauth2UserService;
import com.example.security1.model.UserRole;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


// 1. 코드받기(인증)
// 2.엑세스 토큰(권한)
// 3.사용자 프로필 정보 가져오기
// 4-1. 그 정보(이메일, 전화번호, 이름, 아이디)를 토대로 회원가입을 자동으로 진행
// 4-2. (이메일, 전화번호, 이름, 아이디) 외의 추가 정보를 받아 쇼핑몰 -> (집주소), 백화점몰 -> (vip등급, 일반등급) 회원가입

@Configuration
@EnableWebSecurity // 활성화. 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 애노테이션 활성화, preAuthorize, postAuthorize 애노테이션 활성화
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;

    public SecurityConfig(PrincipalOauth2UserService principalOauth2UserService) {
        this.principalOauth2UserService = principalOauth2UserService;
    }

/*
    // 해당 메서드의 리턴되는 오브젝트를 IoC 로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }*/

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeHttpRequests()
                .requestMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
/*              .requestMatchers("/manager/**").hasAnyRole("ROLE_ADMIN or ROLE_MANAGER") // manager/ 쪽으로 들어오면 관리자 or 매니저
                .requestMatchers("/admin/**").hasRole("ROLE_ADMIN") // admin/ 쪽은 관리자만. hasRole 은 단일 권한*/
                .requestMatchers("/manager/**").hasAnyAuthority(UserRole.ROLE_MANAGER.name(), UserRole.ROLE_ADMIN.name()) // manager/ 쪽으로 들어오면 관리자 or 매니저
                .requestMatchers("/admin/**").hasAuthority(UserRole.ROLE_ADMIN.name()) // manager/ 쪽으로 들어오면 관리자 or 매니저
                .anyRequest().permitAll() // 나머지 주소는 모두 권한 허용
                .and()
                .formLogin()
                .loginPage("/loginForm") // 권한이 필요한 페이지 접근 시 login 페이지로 리다이렉트
                // .usernameParameter("username2") username2로 받고 싶으면 이렇게 명시를 해주어야 함
                .loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                .defaultSuccessUrl("/") // 만약 loginForm 에서 로그인 시 기본적으로 메인 페이지로 이동
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService); // 구글 로그인이 완료된 뒤의 후처리가 필요함. Tip! 코드X, (엑세스토큰 + 사용자프로필정보 O)

        return http.build();
    }
}
