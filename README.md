在实现基于角色的权限管理系统时，结合你描述的表结构和使用Spring Boot与MyBatis的后端框架，可以按照以下步骤组织项目结构：

### 1. 项目结构

以下是一个典型的Spring Boot项目结构，结合MyBatis来实现基于角色的权限管理：

```
src
 └── main
      ├── java
      │    └── com
      │         └── example
      │              └── rbac
      │                   ├── controller
      │                   │    └── UserController.java
      │                   ├── dto
      │                   │    └── UserDTO.java
      │                   ├── entity
      │                   │    ├── Permission.java
      │                   │    ├── Role.java
      │                   │    ├── User.java
      │                   │    ├── UserRole.java
      │                   │    └── RolePermission.java
      │                   ├── mapper
      │                   │    ├── PermissionMapper.java
      │                   │    ├── RoleMapper.java
      │                   │    ├── UserMapper.java
      │                   │    └── UserRoleMapper.java
      │                   ├── service
      │                   │    ├── PermissionService.java
      │                   │    ├── RoleService.java
      │                   │    └── UserService.java
      │                   └── RbacApplication.java
      └── resources
           ├── mapper
           │    ├── PermissionMapper.xml
           │    ├── RoleMapper.xml
           │    ├── UserMapper.xml
           │    └── UserRoleMapper.xml
           ├── application.properties
           └── schema.sql
```

### 2. 实体类

**User.java**
```java
package com.example.rbac.entity;

public class User {
    private Long userId;
    private String userName;
    private String password;
    // Getters and Setters
}
```

**Role.java**
```java
package com.example.rbac.entity;

public class Role {
    private Long roleId;
    private String roleName;
    // Getters and Setters
}
```

**Permission.java**
```java
package com.example.rbac.entity;

public class Permission {
    private Long permissionId;
    private String permissionName;
    // Getters and Setters
}
```

**UserRole.java**
```java
package com.example.rbac.entity;

public class UserRole {
    private Long userId;
    private Long roleId;
    // Getters and Setters
}
```

**RolePermission.java**
```java
package com.example.rbac.entity;

public class RolePermission {
    private Long roleId;
    private Long permissionId;
    // Getters and Setters
}
```

### 3. Mapper 接口

**UserMapper.java**
```java
package com.example.rbac.mapper;

import com.example.rbac.entity.User;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface UserMapper {
    @Select("SELECT * FROM users WHERE user_id = #{userId}")
    User findById(Long userId);
    
    @Insert("INSERT INTO users (user_name, password) VALUES (#{userName}, #{password})")
    void insert(User user);
    
    @Update("UPDATE users SET user_name = #{userName}, password = #{password} WHERE user_id = #{userId}")
    void update(User user);
    
    @Delete("DELETE FROM users WHERE user_id = #{userId}")
    void delete(Long userId);
}
```

其他Mapper（`RoleMapper`、`PermissionMapper`、`UserRoleMapper`、`RolePermissionMapper`）可以遵循类似的结构。

### 4. 服务类

**UserService.java**
```java
package com.example.rbac.service;

import com.example.rbac.entity.User;
import com.example.rbac.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public User getUserById(Long userId) {
        return userMapper.findById(userId);
    }

    public void createUser(User user) {
        userMapper.insert(user);
    }

    public void updateUser(User user) {
        userMapper.update(user);
    }

    public void deleteUser(Long userId) {
        userMapper.delete(userId);
    }
}
```

其他服务类（`RoleService`、`PermissionService`等）可以类似创建。

### 5. 控制器

**UserController.java**
```java
package com.example.rbac.controller;

import com.example.rbac.entity.User;
import com.example.rbac.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/{id}")
    public User getUserById(@PathVariable Long id) {
        return userService.getUserById(id);
    }

    @PostMapping
    public void createUser(@RequestBody User user) {
        userService.createUser(user);
    }

    @PutMapping
    public void updateUser(@RequestBody User user) {
        userService.updateUser(user);
    }

    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
    }
}
```

### 6. 配置文件

**application.properties**
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/rbac_db
spring.datasource.username=root
spring.datasource.password=password
mybatis.mapper-locations=classpath:mapper/*.xml
```

**schema.sql**
```sql
CREATE TABLE users (
    user_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE roles (
    role_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(255) NOT NULL
);

CREATE TABLE permissions (
    permission_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(255) NOT NULL
);

CREATE TABLE user_role (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

CREATE TABLE role_permission (
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(role_id),
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id)
);
```

### 7. 启动类

**RbacApplication.java**
```java
package com.example.rbac;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class RbacApplication {
    public static void main(String[] args) {
        SpringApplication.run(RbacApplication.class, args);
    }
}
```

### 8. MyBatis XML 配置

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

类似地，`RoleMapper.xml`、`PermissionMapper.xml`等也需要配置。

### 总结

这个结构提供了基本的CRUD操作，实际应用中你可能还需要根据需求调整业务逻辑、添加更多功能（如权限检查、用户登录等）。使用Spring Security进行细粒度的权限控制也是推荐的做法。
