package com.example.security1.controller;

import com.example.security1.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.model.UserRole;
import com.example.security1.repository.UserRepository;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller // view를 리턴한다는 뜻
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails) { // DI(의존성 주입). @AuthenticationPrincipal : 세션 정보에 접근할 수 있다.
        System.out.println("/test/login/============================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        
        System.out.println("authentication : " + principalDetails.getUser()); // 1. 다운캐스팅 해서 받기
        System.out.println("userDetails : " + userDetails.getUser()); // 2. @AuthenticationPrincipal 로 받기
        return "세션 정보확인하기";
    }


    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oAuth) {
        System.out.println("/test/oauth/login/============================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        System.out.println("authentication : " + oAuth2User.getAttributes());
        System.out.println("oAuth2User : " + oAuth.getAttributes());
        return "OAuth 세션 정보확인하기";
    }



    public IndexController(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    // localhost:8080/
    // localhost:8080
    @GetMapping({"", "/"})
    public String index() {
        // 머스테치 기본폴더 src/main/resources/
        // 뷰리졸버 설정 : templates(prefix), .mustache(suffix) 생략 가능
        return "index"; // src/main/resources/templates/index.mustache
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails : " + principalDetails.getUser());
        System.out.println("principalDetails : " + principalDetails.getAttributes());
        return "user";
    }
    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }


    // 스프링 시큐리티가 해당 주소를 낚아챔 - SecurityConfig 파일 생성 후 작동안함.
    @GetMapping("/loginForm")
    public String loginForm() { return "loginForm"; }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }


    // api
    @PostMapping("/join")
    public String join(User user) {
        user.setRole(UserRole.ROLE_USER);
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword); // 비밀번호 인코딩
        user.setPassword(encPassword);
        userRepository.save(user); // 회원가입 잘됨. 비밀번호 : 1234 => 시큐리티로 로그인을 할 수 없음. 이유는 패스워드가 암호화되어 있지 않기 때문
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN") // 하나에 걸고 싶을 때
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 여러 개 걸고 싶을 때
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터정보";
    }
}
