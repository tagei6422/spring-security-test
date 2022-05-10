package com.zhj6422.springsecuritytest.provider;

import com.zhj6422.springsecuritytest.entity.IpAuthenticationToken;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class IpAuthenticationProvider implements AuthenticationProvider {
  final static Map<String, SimpleGrantedAuthority> ipAuthorityMap = new ConcurrentHashMap();
  // 维护一个 ip 白名单列表，每个 ip 对应一定的权限
  static {
    ipAuthorityMap.put("127.0.0.1", new SimpleGrantedAuthority("ADMIN"));
    ipAuthorityMap.put("10.236.69.103", new SimpleGrantedAuthority("ADMIN"));
    ipAuthorityMap.put("10.236.69.104", new SimpleGrantedAuthority("FRIEND"));
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    IpAuthenticationToken ipAuthenticationToken = (IpAuthenticationToken) authentication;
    String ip = ipAuthenticationToken.getIp();
    SimpleGrantedAuthority simpleGrantedAuthority = ipAuthorityMap.get(ip);
    // 不在白名单列表中
    if (simpleGrantedAuthority == null) {
      return null;
    } else {
      // 封装权限信息，并且此时身份已经被认证
      return new IpAuthenticationToken(ip, Arrays.asList(simpleGrantedAuthority));
    }
  }

  // 只支持 IpAuthenticationToken 该身份
  @Override
  public boolean supports(Class<?> authentication) {
    return (IpAuthenticationToken.class
        .isAssignableFrom(authentication));
  }
}

