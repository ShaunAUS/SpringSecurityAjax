package corespringsecurity.security.config;


import corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import corespringsecurity.security.provider.AjaxAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {


    // ajaxProvider을 스프링 시큐리티가 사용하게
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Bean
    private AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();

    }

    @Bean
    private AjaxAuthenticationSuccessHandler authenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    private AjaxAuthenticationFailureHandler authenticationFailureHandler(){
        return new AjaxAuthenticationFailureHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                //추가하고자하는 필터가 기존 필터 앞에 위치할떄( usernamePassFilter보다 Ajax필터를 앞에 위치시킴)
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
        //post 방식은 csrf 여부 검사한다
        http.csrf().disable();

    }


    //필터에 완성된 handler들이나 etc.. 등등 설정 끼워주기
    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());

        return ajaxLoginProcessingFilter;
    }
}
