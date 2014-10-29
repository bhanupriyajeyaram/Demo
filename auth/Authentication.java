package com.fsa.auth;

import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

public class Authentication {
	
	static private final Logger log = Logger.getLogger(Authentication.class);

	public Subject userAuthenticate(String userName, String password) throws IncorrectCredentialsException{
		
		Subject user=null;
		
			try{
			
			
			Factory<org.apache.shiro.mgt.SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
			org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
			
			SecurityUtils.setSecurityManager(securityManager);
			user = SecurityUtils.getSubject();
			
			UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
			token.setRememberMe(true);
				try{
					user.login(token);
				}catch(UnknownSessionException use){
					user = new Subject.Builder().buildSubject();
					user.login(token);
				}
			}catch(Exception e){
				log.info(e.getMessage()+e);
				return null;
			}
		return user;
	}
}
