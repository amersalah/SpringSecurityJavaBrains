package com.amer.securitytest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


    //Used for Authentication
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //set Configuration to auth Object
        auth.inMemoryAuthentication().withUser("Amer")
                                     .password("123456")
                                        .roles("USER")
                .and()
                .withUser("Ahmed")
                .password("987654")
                .roles("ADMIN");
    }


    //Used for Authorization
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("USER" , "ADMIN")
                .antMatchers("/").permitAll()
                .and().formLogin()
        ;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder()
    {
        return NoOpPasswordEncoder.getInstance();
    }



}
