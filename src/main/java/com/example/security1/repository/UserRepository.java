package com.example.security1.repository;

import com.example.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

// CRUD 함수를 JpaRepository 가 들고 있음
// @Repository 라는 애노테이션 없어도 IoC 된다. 이유는 JpaRepository 를 상속했기 때문.
@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    public Optional<User> findByUsername(String username);

}
