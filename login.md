要为你的基于角色的权限管理系统实现用户登录功能，我们可以添加以下内容：

1. **用户登录 DTO**：用于接收用户的登录请求数据。
2. **用户登录接口和服务**：用于处理用户登录逻辑。
3. **简单的 JWT 生成与验证**：用于登录后生成令牌和验证用户身份。
4. **配置类**：用于配置 JWT 和安全相关的属性。

### 1. 用户登录 DTO

创建一个简单的数据传输对象（DTO）来接收登录请求。

**LoginRequest.java**
```java
package com.example.rbac.dto;

public class LoginRequest {
    private String userName;
    private String password;

    // Getters and Setters
}
```

**LoginResponse.java**
```java
package com.example.rbac.dto;

public class LoginResponse {
    private String token;

    public LoginResponse(String token) {
        this.token = token;
    }

    // Getter
}
```

### 2. 用户登录服务

在服务层添加一个登录方法，验证用户名和密码，然后生成 JWT 令牌。

**UserService.java**
```java
package com.example.rbac.service;

import com.example.rbac.dto.LoginRequest;
import com.example.rbac.dto.LoginResponse;
import com.example.rbac.entity.User;
import com.example.rbac.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    @Autowired
    private JwtUtil jwtUtil;

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public LoginResponse login(LoginRequest request) {
        User user = userMapper.findByUserName(request.getUserName());
        if (user != null && passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            String token = jwtUtil.generateToken(user);
            return new LoginResponse(token);
        } else {
            throw new RuntimeException("Invalid username or password");
        }
    }

    public void createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userMapper.insert(user);
    }
}
```

### 3. 用户登录控制器

创建一个控制器来处理用户登录请求。

**AuthController.java**
```java
package com.example.rbac.controller;

import com.example.rbac.dto.LoginRequest;
import com.example.rbac.dto.LoginResponse;
import com.example.rbac.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        return userService.login(request);
    }
}
```

### 4. JWT 工具类

编写一个简单的 JWT 工具类来生成和验证令牌。

**JwtUtil.java**
```java
package com.example.rbac.util;

import com.example.rbac.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {
    private String secret = "secretKey";
    private long expiration = 86400000; // 1 day in milliseconds

    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUserName())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token, User user) {
        Claims claims = getClaimsFromToken(token);
        return claims.getSubject().equals(user.getUserName()) && !claims.getExpiration().before(new Date());
    }
}
```

### 5. 更新 UserMapper

需要一个新的查询方法来根据用户名查找用户。

**UserMapper.java**
```java
package com.example.rbac.mapper;

import com.example.rbac.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {
    @Select("SELECT * FROM users WHERE user_name = #{userName}")
    User findByUserName(String userName);
}
```

### 6. 安全配置

配置 Spring Security 以支持 JWT 认证。

**SecurityConfig.java**
```java
package com.example.rbac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/auth/login").permitAll()
            .anyRequest().authenticated()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}
```

**JwtAuthenticationFilter.java**
```java
package com.example.rbac.config;

import com.example.rbac.util.JwtUtil;
import com.example.rbac.entity.User;
import com.example.rbac.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserMapper userMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String token = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
            username = jwtUtil.getClaimsFromToken(token).getSubject();
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User user = userMapper.findByUserName(username);

            if (jwtUtil.validateToken(token, user)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        user, null, null);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }
}
```

### 总结

以上实现了用户登录功能，用户通过发送用户名和密码到`/auth/login`端点获得一个JWT令牌。这个令牌将用于授权后续的请求。对于实际项目，应加强密码存储和传输的安全性（如使用HTTPS），并对JWT进行更多的安全处理，如使用更复杂的密钥、过期时间和刷新机制。
