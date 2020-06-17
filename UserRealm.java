package com.jx.mns.shiro;

import com.jx.mns.common.consts.CoreRolesEnum;
import com.jx.mns.modules.system.dto.QueryUserDto;
import com.jx.mns.modules.system.service.MenuService;
import com.jx.mns.modules.system.service.TenantService;
import com.jx.mns.modules.system.service.UserService;
import com.jx.mns.modules.system.vo.TenantVo;
import com.jx.mns.modules.system.vo.UserVo;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

/**
 *
 * @author yusijiayf1 2020.04.23
 */
public class UserRealm extends AuthorizingRealm {

    @Autowired
    private UserService userService;
    @Autowired
    private MenuService menuService;
    @Autowired
    private TenantService tenantService;

    /**
     * shiro授权方法
     * 强制重写
     *
     * @param principals 相当于账户名
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals){
        //授权接口，在这里给用户授权   （鉴权）
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        Subject subject = SecurityUtils.getSubject();
        UserVo userVo = (UserVo) subject.getPrincipal();
        //获取用户的auth权限字段
        authorizationInfo.addStringPermissions(menuService.getUserAuth(userVo.getId()));
        return authorizationInfo;
    }

    /**
     * 登陆使用，认证用户是否可以进入系统
     * 强制重写
     *
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        //认证用户是否可以登陆系统    （登陆）
        String clientAccountName = (String) token.getPrincipal();
        String clientPassword = new String((char[]) token.getCredentials());
        //正常的话会出现查询
        UserVo userVo = userService.getUserByAccountNameAndPassword(new QueryUserDto(clientAccountName));
        if(userVo==null){
            return null;
        }

        if(!CoreRolesEnum.SUPER_ADMIN.getRoleId().equals(userVo.getRoleId())
                && !CoreRolesEnum.TENANT.getRoleId().equals(userVo.getRoleId())){
            // 既不是超级管理员，也不是租户管理员，是某个租户的子管理员，查询父管理员的租户信息作为自己的租户信息
            TenantVo tenantVo = tenantService.getTenantByUserId(userVo.getCreatorId());
            userVo.setTenantInfo(tenantVo);
        }

        String passwordFromDB = userVo.getPassword();
        /**
         * 返回一个从数据库中查出来的的凭证。用户名为clientUsername，密码为passwordFromDB 。封装成当前返回值
         * 接下来shiro框架做的事情就很简单了。
         * 它会拿你的输入的token与当前返回的这个数据库凭证 SimpleAuthenticationInfo对比一下
         * 看看是不是一样，如果用户的帐号密码与数据库中查出来的数据一样，那么本次登录成功
         * 否则就是你密码输入错误。
         *
         * 这里是交给AuthenticatingRealm使用 CredentialsMatcher进行密码匹配
         */
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(userVo, passwordFromDB, getName());
        return authenticationInfo;
    }

//    @Override
//    public boolean supports(AuthenticationToken token) {
//        return token instanceof AuthToken;
//    }

    /**
     * 设置认证加密方式
     */
    @Override
    public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
        super.setCredentialsMatcher(new CustomCredentialsMatcher());
    }
}
