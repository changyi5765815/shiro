package com.atguigu.shiro.handlers;

import org.apache.shiro.authz.UnauthorizedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ShiroExceptionHandler {

	@ExceptionHandler({UnauthorizedException.class})
	public String handleShiroException(Exception ex){
		System.out.println(ex);
		return "redirect:/unauthorized.jsp";
	}
	
}
