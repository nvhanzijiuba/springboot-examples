package com.neo.sevice;

import com.neo.model.LoginResult;
import org.apache.shiro.session.Session;

/**
 * @Author: xu.dm
 * @Date: 2018/8/11 21:34
 * @Description:
 */
public interface LoginService {
    LoginResult login(String userName, String password);
    String getCurrentUserName();
    Session getSession();
    void logout();
}
