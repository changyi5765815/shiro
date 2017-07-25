package com.atguigu.shiro.realms;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class MyShiroRealm extends AuthorizingRealm{

	// 授权时 shiro 会回调的方法. 
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		//1. 从 PrincipalCollection 参数中来获取登录的实体信息. 
		//即创建 SimpleAuthenticationInfo 对象时的 pricipal
		Object principal = principals.getPrimaryPrincipal();
		
		//2. principal 中肯能已经包含了对应的权限信息. 
		//若没有, 则根据 principal 来查询数据库得到当前用户有的权限信息
		Set<String> roles = new HashSet<>();
		roles.add("user");
		
		if("admin".equals(principal)){
			roles.add("admin");
		}
		
		//3. 把权限信息封装为 SimpleAuthorizationInfo 对象并返回
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);
		return info;
	}

	// 认证时 shiro 会回调的方法
	/**
	 * 1. 参数 AuthenticationToken 即为在 Handler 中调用 Subject login 方法时传入的那个 UsernamePasswordToken
	 * 2. 所以可以从 token 中获取用户名. 
	 * 3. 
	 * 4. 密码的比对是由 shiro 来完成的
	 * 1). 调用 Subject login 方法时会保存从前台输入的密码
	 * 2). 返回 SimpleAuthenticationInfo 对象的时候, 会保存从数据库中取得的密码
	 * 
	 * 5. 如何能知道密码是如何进行比对的呢 ? 
	 * 6. 关于密码的加密:
	 * 1). 基本思路: 在 Spring 的 IOC 容器中配置一个 CredentialsMatcher 类型的 bean. 并把其配置为 ShiroRealm 的 
	 * credentialsMatcher 属性
	 * 2). 默认情况下下, 使用的 CredentialsMatcher 类型的实例为: SimpleCredentialsMatcher
	 * 3). 通常情况下使用密码的 MD5 盐值加密. 
	 * ①. 为 realm 配置一个 CredentialsMatcher 实例. 具体参见 applicationContext.xml 文件. 
	 * ②. doGetAuthenticationInfo 方法的返回值需要调用 
	 * SimpleAuthenticationInfo.SimpleAuthenticationInfo(Object principal, 
	 * 	Object hashedCredentials, ByteSource credentialsSalt, String realmName) 构造器.
	 * ③. 一般滴,可以通过 ByteSource.Util.bytes(String) 来计算盐值. 而数据库中保存的是 String
	 * ④. 通过 
	 * SimpleHash.SimpleHash(String algorithmName, Object source, Object salt, int hashIterations)
	 * 来计算加密后的密码. 
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		//1. 把 AuthenticationToken 强转为 UsernamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		
		//2. 从 UsernamePasswordToken 中获取 username
		String username = upToken.getUsername();
		
		//3. 利用 username 从数据库中获取对应的用户信息. 包括密码
		System.out.println("利用 username[" + username + "]从数据库中获取用户的信息");
		
		if("unknown".equals(username)){
			throw new UnknownAccountException("用户名不存在");
		}
		if("monster".equals(username)){
			throw new LockedAccountException("用户名被锁定");
		}
		
		//4. 把用户信息封装为一个 SimpleAuthenticationInfo 对象, 并返回
		//认证的实体信息. 可以是一个 User 对象. 也可以是 username .
		Object principal = username;
		//从数据库中取得的密码
		Object credentials = null;
		//盐值加密的 盐
		ByteSource salt = ByteSource.Util.bytes(username);
		if("user".equals(username)){
			credentials = "098d2c478e9c11555ce2823231e02ec1";
		}
		else if("admin".equals(username)){
			credentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		
		//当前 Realm 的 name 属性值. 可以直接调用父类的 getName() 方法来获取
		String realmName = getName();
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, salt, realmName);
		
		return info;
	}
	
	public static void main(String[] args) {
		String algorithmName = "MD5";
		String source = "123456";
		Object salt = ByteSource.Util.bytes("admin");
		int hashIterations = 1024;
		Object result = new SimpleHash(algorithmName, source, salt, hashIterations);
		System.out.println(result);
		
		ApplicationContext ctx = new ClassPathXmlApplicationContext("applicationContext.xml");
		Map<String, String> map = (Map<String, String>) ctx.getBean("filterChainDefinitionMap");
		System.out.println(map);
	}

}
