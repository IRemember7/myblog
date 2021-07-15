package com.star.controller.admin;

import com.star.entity.User;
import com.star.service.UserService;
import com.star.util.MD5Utils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpSession;

/**
 * @Description: 用户登录控制器
 * @Author: ONESTAR
 * @Date: Created in 9:54 2020/3/27
 * @QQ群: 530311074
 * @URL: https://onestar.newstar.net.cn/
 */
@Controller
@RequestMapping("/admin")
public class LoginController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private UserService userService;

    /**
     * @Description: 跳转登录页面
     * @Auther: ONESTAR
     * @Date: 9:57 2020/3/27
     * @Param:
     * @Return: 返回登录页面
     */
    @GetMapping
    public String loginPage(){
        return "admin/login";
    }

    /**
     * @Description: 登录校验
     * @Auther: ONESTAR
     * @Date: 10:04 2020/3/27 
     * @Param: username:用户名
     * @Param: password:密码
     * @Param: session:session域
     * @Param: attributes:返回页面消息
     * @Return: 登录成功跳转登录成功页面，登录失败返回登录页面
     */
    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpSession session,
                        RedirectAttributes attributes) {

        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, MD5Utils.code(password));
        try {
            //进行验证，这里可以捕获异常，然后返回对应信息
            subject.login(usernamePasswordToken);
        } catch (UnknownAccountException e) {
            logger.error("用户名不存在！", e);
            attributes.addFlashAttribute("message", "用户名不存在");
            return "redirect:/admin";
        } catch (AuthenticationException e) {
            attributes.addFlashAttribute("message", "用户名和密码错误");
            logger.error("账号或密码错误！", e);
            return "redirect:/admin";
        }
        session.setAttribute("user", userService.getUserByName(username));
        return "redirect:/adminMain";
    }

    /**
     * @Description: 注销
     * @Auther: ONESTAR
     * @Date: 10:15 2020/3/27
     * @Param: session:session域
     * @Return: 返回登录页面
     */
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        Subject subject = SecurityUtils.getSubject();
        session.removeAttribute("user");
        subject.logout();
        return "redirect:/admin";
    }

}