package io.getarrays.userservice.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.getarrays.userservice.domain.User;

@Repository
public interface UserRipo extends JpaRepository<User, Long> {
	User findByUsername(String username);
}
