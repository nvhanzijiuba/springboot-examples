package com.neo.web;

import com.neo.model.LoginResult;
import com.neo.model.UserInfo;
import com.neo.sevice.LoginService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Controller
public class HomeController {

    @Autowired
    LoginService loginService;

    @RequestMapping({"/","/index"})
    public String index(){
        return"/index";
    }

    @RequestMapping(value = "/login",method = RequestMethod.GET)
    public String toLogin(Map<String, Object> map,HttpServletRequest request)
    {
        loginService.logout();
        return "/login";
    }

    @RequestMapping(value = "/login",method = RequestMethod.POST)
    public String login(Map<String, Object> map,HttpServletRequest request) throws Exception{
        System.out.println("login()");
        String userName = request.getParameter("userName");
        String password = request.getParameter("password");

        LoginResult loginResult = loginService.login(userName,password);
        if(loginResult.isLogin())
        {
            return "/index";
        }
        else {
            map.put("msg",loginResult.getResult());
            map.put("userName",userName);
            return "/login";
        }
    }

    @RequestMapping(value = "/loginaa",method = RequestMethod.POST)
    public Object loginaa(@RequestParam String username,@RequestParam String password) throws Exception {
        System.out.println("HomeController.loginaa()");
        SecurityUtils.getSubject().logout();
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        Map<String, Object> map = new HashMap<>();
        try {
            subject.login(token);
            String sessionid = (String) subject.getSession().getId();
            System.out.println("sessionid======"+sessionid);
            map.put("msg", sessionid);
            return "/index";

        } catch (AuthenticationException e) {
          String msg= "用户名或者密码不正确";
            map.put("msg", msg);
            // 此方法不处理登录成功,由shiro进行处理
            return "/login";
        }
    }

    //被踢出后跳转的页面
    @RequestMapping(value = "/kickout", method = RequestMethod.GET)
    public String kickOut() {
        return "/kickOut2";
    }

    @RequestMapping("/403")
    public String unauthorizedRole(){
        System.out.println("------没有权限-------");
        return "403";
    }

}