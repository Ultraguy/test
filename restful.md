在你的基于角色的权限管理系统中，实现 RESTful 风格的接口，并使用标准的 HTTP 状态码进行与前端的交互，可以通过以下步骤实现：

### 1. 标准化 HTTP 状态码

确保每个接口根据操作结果返回合适的 HTTP 状态码。例如：
- **200 OK**: 成功获取数据或成功执行操作。
- **201 Created**: 成功创建资源。
- **400 Bad Request**: 请求参数错误。
- **401 Unauthorized**: 用户认证失败。
- **403 Forbidden**: 用户没有访问权限。
- **404 Not Found**: 请求的资源不存在。
- **500 Internal Server Error**: 服务器内部错误。

### 2. 修改 DTO 和服务类

调整 `LoginResponse` 添加 `tokenType`，更新 `UserService` 和 `AuthController` 以支持 RESTful 响应。

**LoginResponse.java**
```java
package com.example.rbac.dto;

public class LoginResponse {
    private String token;
    private String tokenType = "Bearer";

    public LoginResponse(String token) {
        this.token = token;
    }

    // Getters and Setters
}
```

### 3. 调整服务类

确保服务层的逻辑合理并返回合适的响应。

**UserService.java**
```java
package com.example.rbac.service;

import com.example.rbac.dto.LoginRequest;
import com.example.rbac.dto.LoginResponse;
import com.example.rbac.entity.User;
import com.example.rbac.mapper.UserMapper;
import com.example.rbac.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

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
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
    }

    public void createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userMapper.insert(user);
    }

    public User getUserById(Long userId) {
        return userMapper.findById(userId);
    }

    public void updateUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userMapper.update(user);
    }

    public void deleteUser(Long userId) {
        userMapper.delete(userId);
    }
}
```

### 4. 调整控制器

在控制器中使用适当的 HTTP 状态码和响应实体（`ResponseEntity`）。

**AuthController.java**
```java
package com.example.rbac.controller;

import com.example.rbac.dto.LoginRequest;
import com.example.rbac.dto.LoginResponse;
import com.example.rbac.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse response = userService.login(request);
        return ResponseEntity.ok(response);
    }
}
```

**UserController.java**
```java
package com.example.rbac.controller;

import com.example.rbac.entity.User;
import com.example.rbac.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @PostMapping
    public ResponseEntity<Void> createUser(@RequestBody User user) {
        userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PutMapping("/{id}")
    public ResponseEntity<Void> updateUser(@PathVariable Long id, @RequestBody User user) {
        user.setUserId(id);
        userService.updateUser(user);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

### 5. 全局异常处理

使用 `@ControllerAdvice` 处理全局异常，并返回适当的 HTTP 状态码和消息。

**GlobalExceptionHandler.java**
```java
package com.example.rbac.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<String> handleResponseStatusException(ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatus()).body(ex.getReason());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
    }
}
```

### 6. 修改 JWT 工具类和过滤器

确保 `JwtAuthenticationFilter` 返回 401 错误代码当令牌无效或丢失时。

**JwtAuthenticationFilter.java**
```java
package com.example.rbac.config;

import com.example.rbac.util.JwtUtil;
import com.example.rbac.entity.User;
import com.example.rbac.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
```

### 7. 修改 `UserMapper` XML 配置

**UserMapper.xml**
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.rbac.mapper.UserMapper">
    <resultMap id="UserResultMap" type="com.example.rbac.entity.User">
        <id property="userId" column="user_id"/>
        <result property="userName" column="user_name"/>
        <result property="password" column="password"/>
    </resultMap>

    <select id="findById" resultMap="UserResultMap">
        SELECT * FROM users WHERE user_id = #{userId}
    </select>

    <select id="findByUserName" resultMap="UserResultMap">
        SELECT * FROM users WHERE user_name = #{userName}
    </select>

    <insert id="insert">
        INSERT INTO users (user_name, password) VALUES (#{userName}, #{password})
    </insert>

    <update id="update">
        UPDATE users SET user_name = #{userName}, password = #{password} WHERE user_id = #{userId}
    </update>

    <delete id="delete">
        DELETE FROM users WHERE user_id = #{userId}
    </delete>
</mapper>
```

### 总结

1. **使用标准的 HTTP 状态码**：为成功、失败等不同场景返回相应的状态码。
2. **通过 `ResponseEntity` 返回响应**：控制器中使用 `ResponseEntity` 处理不同的 HTTP 状态。
3. **全局异常处理**：使用 `@ControllerAdvice` 统一处理异常。
4. **JWT 认证**：在 JWT
