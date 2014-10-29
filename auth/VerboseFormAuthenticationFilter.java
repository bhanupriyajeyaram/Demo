package com.fsa.auth;

import javax.servlet.ServletRequest;

import org.apache.log4j.Logger;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;

public class VerboseFormAuthenticationFilter extends FormAuthenticationFilter {
	static private final Logger log = Logger.getLogger(VerboseFormAuthenticationFilter.class);
	
	@Override
	protected void setFailureAttribute(ServletRequest request, AuthenticationException ae) {
		log.info("Executing............setFailureAttribute");
		String message = ae.getMessage();
		log.info("message........"+message);
		request.setAttribute(getFailureKeyAttribute(), message);
	}
}
