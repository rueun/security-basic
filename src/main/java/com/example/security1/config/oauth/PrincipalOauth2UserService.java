package com.example.security1.config.oauth;

import com.example.security1.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.model.UserRole;
import com.example.security1.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    public PrincipalOauth2UserService(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
    }


    // 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료 시 @AuthenticationPrincipal 애노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration:" + userRequest.getClientRegistration()); // registrationId 로 어떤 OAuth로 로그인 했는지 확인
        System.out.println("getAccessToken:" + userRequest.getAccessToken().getTokenValue());

        OAuth2User oauth2User = super.loadUser(userRequest);
        // 구글로그인 버튼 클릑 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
        // userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원프로필을 받아준다.
        System.out.println("getAttributes:" + oauth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getRegistrationId(); // google
        String providerId = oauth2User.getAttribute("sub"); // 103263310848991511006
        String username = provider + "_" + providerId; // google_103263310848991511006
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oauth2User.getAttribute("email");

        final User user = userRepository.findByUsername(username)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .username(username)
                            .password(password)
                            .email(email)
                            .role(UserRole.ROLE_USER)
                            .provider(provider)
                            .providerId(providerId)
                            .build();

                    return userRepository.save(newUser);
                });

        return new PrincipalDetails(user, oauth2User.getAttributes());
    }
}
