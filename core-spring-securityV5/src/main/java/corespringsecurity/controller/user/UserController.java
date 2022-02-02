package corespringsecurity.controller.user;

import corespringsecurity.domain.Account;
import corespringsecurity.domain.AccountDTo;
import corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

     private UserService userService;
     private PasswordEncoder passwordEncoder;



    @GetMapping("/mypage")
    public String myPage(){

        return "user/mypage";

    }

    @GetMapping("/users")
    public String create(){

        return "user/login/register";

    }

    @PostMapping("/users")
    public String createUser(AccountDTo accountDTo){

        ModelMapper modelMapper =new ModelMapper();
        Account account = modelMapper.map(accountDTo, Account.class);
        account.setPassWord(passwordEncoder.encode(account.getPassWord()));
        userService.createUser(account);


        return "redirect:/";

    }


}
