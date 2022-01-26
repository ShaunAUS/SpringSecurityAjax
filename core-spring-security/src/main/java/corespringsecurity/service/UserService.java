package corespringsecurity.service;

import corespringsecurity.domain.Account;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    void createUser(Account account);
}
