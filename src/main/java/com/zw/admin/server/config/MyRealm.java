package com.zw.admin.server.config;

import com.zw.admin.server.dao.PermissionDao;
import com.zw.admin.server.dao.RoleDao;
import com.zw.admin.server.model.Permission;
import com.zw.admin.server.model.Role;
import com.zw.admin.server.model.User;
import com.zw.admin.server.service.PermissionService;
import com.zw.admin.server.service.RoleService;
import com.zw.admin.server.service.UserService;
import com.zw.admin.server.utils.SpringUtil;
import com.zw.admin.server.utils.UserUtil;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class MyRealm extends AuthorizingRealm {
    private static final Logger LOGGER = LoggerFactory.getLogger("adminLogger");

    @Autowired
    UserService userService;

    @Autowired
    RoleService roleService;

    @Autowired
    PermissionService permissionService;

    /**
     * 认证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) authenticationToken;

        String username = usernamePasswordToken.getUsername();
        UserService userService = SpringUtil.getBean(UserService.class);
        User user = userService.getUser(username);
        if (user == null)
            throw new UnknownAccountException("用户名不存在");

        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username, user.getPassword(), ByteSource.Util.bytes(user.getSalt()), getName());

        if (!user.getPassword()
                .equals(userService.passwordEncoder(new String(usernamePasswordToken.getPassword()), user.getSalt()))) {
            throw new IncorrectCredentialsException("密码错误");
        }

        if (user.getStatus() != User.Status.VALID) {
            throw new IncorrectCredentialsException("无效状态，请联系管理员");
        }

        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, user.getPassword(),
                ByteSource.Util.bytes(user.getSalt()), getName());

        UserUtil.setUserSession(user);

        return simpleAuthenticationInfo;
    }

    /**
     * 授权
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        LOGGER.debug("权限配置");

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        User user = UserUtil.getCurrentUser();

        List<Role> roles = SpringUtil.getBean(RoleDao.class).listByUserId(user.getId());
        Set<String> roleNames = roles.stream().map(Role::getName).collect(Collectors.toSet());
        simpleAuthorizationInfo.setRoles(roleNames);
        List<Permission> permissionList = SpringUtil.getBean(PermissionDao.class).listByUserId(user.getId());
        UserUtil.setPermissionSession(permissionList);
        Set<String> permissions = permissionList.stream().filter(p -> !StringUtils.isEmpty(p.getPermission()))
                .map(Permission::getPermission).collect(Collectors.toSet());
        simpleAuthorizationInfo.setStringPermissions(permissions);

        return null;
    }

    public static void main(String[] args){
//        Random random = new Random();
//        random.doubles().limit(10).forEach(System.out::println);

        List<String> list = Arrays.asList("a","","c");
        List l = list.stream().filter(x->!StringUtils.isEmpty(x)).collect(Collectors.toList());
        for(Object s : l)
            System.out.println(s +"\n");
    }
}

