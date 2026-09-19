package com.hdfc.secureauth.repository;

import com.hdfc.secureauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {
}