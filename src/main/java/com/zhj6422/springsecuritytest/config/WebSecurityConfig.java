package com.zhj6422.springsecuritytest.config;

import com.zhj6422.springsecuritytest.filter.IpAuthenticationProcessingFilter;
import com.zhj6422.springsecuritytest.provider.IpAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
* EnableWebSecurity注解使SpringMVC继承了web安全支持
* */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  //ip 认证者配置
  @Bean
  IpAuthenticationProvider ipAuthenticationProvider() {
    return new IpAuthenticationProvider();
  }

  // 配置封装 ipAuthenticationToken 的过滤器
  IpAuthenticationProcessingFilter ipAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
    IpAuthenticationProcessingFilter ipAuthenticationProcessingFilter = new IpAuthenticationProcessingFilter();
    // 为过滤器添加认证器
    ipAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager);
    // 重写认证失败时的跳转页面
    ipAuthenticationProcessingFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/ipLogin?error"));
    return ipAuthenticationProcessingFilter;
  }

  // 配置登录端点
  @Bean
  LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint(){
    LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/ipLogin");
    return loginUrlAuthenticationEntryPoint;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/", "/home").permitAll()
        .antMatchers("/ipLogin").permitAll()
        .anyRequest().authenticated()
        .and()
        .logout()
        .logoutSuccessUrl("/")
        .permitAll()
        .and()
        .exceptionHandling()
        .accessDeniedPage("/ipLogin")
        .authenticationEntryPoint(loginUrlAuthenticationEntryPoint())
    ;

    // 注册 IpAuthenticationProcessingFilter  注意放置的顺序 这很关键
    http.addFilterBefore(ipAuthenticationProcessingFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);

  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    // 添加自定义的ipAuthenticationProvider
    auth.authenticationProvider(ipAuthenticationProvider());
  }
}
