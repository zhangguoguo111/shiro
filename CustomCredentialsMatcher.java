package com.jx.mns.shiro;

import com.jx.mns.modules.system.vo.UserVo;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.subject.Subject;
import org.springframework.util.DigestUtils;


public class CustomCredentialsMatcher extends SimpleCredentialsMatcher {


    @Override
    public boolean doCredentialsMatch(AuthenticationToken authcToken, AuthenticationInfo info) {

        UsernamePasswordToken token = (UsernamePasswordToken) authcToken;

        Object tokenCredentials = encrypt(String.valueOf(token.getPassword()), info.getPrincipals().getPrimaryPrincipal());
        Object accountCredentials = getCredentials(info);
        //将密码加密与系统加密后的密码校验，内容一致就返回true,不一致就返回false
        return equals(tokenCredentials, accountCredentials);
    }

    //密码加密方法
    private String encrypt(String clientPassword, Object userObjectDB) {
        Subject subject = SecurityUtils.getSubject();
        UserVo user = (UserVo) userObjectDB;
        clientPassword += "/" + user.getSalt();
        String encryptionPw = DigestUtils.md5DigestAsHex(clientPassword.getBytes());
        return encryptionPw;
    }
}
