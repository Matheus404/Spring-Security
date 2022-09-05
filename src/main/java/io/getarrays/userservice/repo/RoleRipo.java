package io.getarrays.userservice.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import io.getarrays.userservice.domain.Role;

public interface RoleRipo extends JpaRepository<Role, Long>{
	Role findByName(String name);
}
