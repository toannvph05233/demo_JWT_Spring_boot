package com.codegym.demo.service;

import com.codegym.demo.model.AppUser;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

public interface IUserService extends UserDetailsService {
    List<AppUser> getAll();
    void save(AppUser appUser);
    void delete(Long id);
}
