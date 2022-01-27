package com.codegym.demo.repository;

import com.codegym.demo.model.AppUser;
import org.springframework.data.repository.CrudRepository;

public interface AppUserRepo extends CrudRepository<AppUser, Long> {
    AppUser findByUserName(String userName);
}
