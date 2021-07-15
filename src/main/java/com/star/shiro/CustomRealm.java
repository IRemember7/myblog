package com.star.shiro;

import com.star.entity.User;
import com.star.service.UserService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;

/**
 * @author lianghanmao
 * @date 2021年07月14日 下午4:43
 */
public class CustomRealm extends AuthorizingRealm {

    @Autowired
    private UserService userService;

    /**
     * @MethodName doGetAuthorizationInfo
     * @Description 权限配置类
     * @Param [principalCollection]
     * @Return AuthorizationInfo
     */

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取登录用户名
        String name = (String) principalCollection.getPrimaryPrincipal();
        //查询用户名称
        User user = userService.getUserByName(name);
        //添加角色和权限
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        //添加角色
        simpleAuthorizationInfo.addRole(user.getUsername());
        //添加权限
        simpleAuthorizationInfo.addStringPermission("admin");
        return simpleAuthorizationInfo;
    }


    /**
     * @MethodName doGetAuthenticationInfo
     * @Description 认证配置类
     * @Param [authenticationToken]
     * @Return AuthenticationInfo
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (StringUtils.isEmpty(authenticationToken.getPrincipal())) {
            return null;
        }
        //获取用户信息
        String name = authenticationToken.getPrincipal().toString();
        User user = userService.getUserByName(name);
        if (user == null) {
            //这里返回后会报出对应异常
            return null;
        } else {
            //这里验证authenticationToken和simpleAuthenticationInfo的信息
            SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(name, user.getPassword(), getName());
            return simpleAuthenticationInfo;
        }
    }
}
