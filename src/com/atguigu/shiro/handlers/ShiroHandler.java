package com.atguigu.shiro.handlers;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.atguigu.shiro.services.ShiroService;

@Controller
public class ShiroHandler {

	@Autowired
	private ShiroService shiroService;
	
	@RequestMapping("/testShiroAnnotation")
	public String testShiroAnnotation(){
		shiroService.testMethod();
		return "redirect:/success.jsp";
	}
	
	@RequestMapping(value="/shiroLogin", method=RequestMethod.POST)
	public String login(@RequestParam("username") String username,
			@RequestParam("password") String password){
		// 获取 Subject 对象. Subject 即为当前用户. 调用 SecurityUtils.getSubject(); 进行获取. 
        Subject currentUser = SecurityUtils.getSubject();
        
     // 测试当前 Subject 是否已经被认证. 即是否已经登录. 调用 Subject 的 isAuthenticated() 方法. 
        if (!currentUser.isAuthenticated()) {
        	// 把用户名和密码封装为一个 UsernamePasswordToken 对象. 
        	// 直接调换用 UsernamePasswordToken 的构造器即可. 
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            token.setRememberMe(true);
            try {
            	// 执行登陆操作. 
            	// 调用 Subject 的 login(AuthenticationToken) 方法
            	// 这说明 UsernamePasswordToken 是 AuthenticationToken 的实现类或子类
                currentUser.login(token);
            } 
            // ... catch more exceptions here (maybe custom ones specific to your application?
            // 认证异常的父类. 以上的异常都是该异常的子类. 
            catch (AuthenticationException ae) {
            	System.out.println("登录失败: " + ae.getMessage());
            	return "redirect:/login.jsp";
            }
        }
        
		return "redirect:/success.jsp";
	}
	
}
