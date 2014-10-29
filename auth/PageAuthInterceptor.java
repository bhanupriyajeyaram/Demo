package com.fsa.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.subject.Subject;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

public class PageAuthInterceptor implements HandlerInterceptor {

	@Override
	public void afterCompletion(HttpServletRequest arg0,
			HttpServletResponse arg1, Object arg2, Exception arg3)
			throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void postHandle(HttpServletRequest arg0, HttpServletResponse response,
			Object arg2, ModelAndView arg3) throws Exception {
		response.addHeader(
				"Cache-Control",
				"no-cache,no-store,private,must-revalidate,max-stale=0,post-check=0,pre-check=0");
		response.addHeader("Pragma", "no-cache");
		response.addDateHeader("Expires", 0);

	}

	@Override
	public boolean preHandle(HttpServletRequest request,
			HttpServletResponse response, Object arg2) throws Exception {
		String uri = request.getRequestURI();
		if (!uri.endsWith("login.htm") && !uri.endsWith("logOut.htm")
				&& !uri.endsWith("recoverPasswordMail.htm")
				&& !uri.endsWith("passwordChanged.htm")
				&& !uri.endsWith("validateUser.htm")
				&& !uri.endsWith("passWordAuthentcation.htm")) {
			try{
				Subject subj = (Subject) request.getSession().getAttribute("currentUser");
			if (subj.getSession().getTimeout() < 0 || subj.getSession() == null ||subj.isAuthenticated() == false ) {
				response.sendRedirect("login.htm");
				return false;
			}else{
				subj.getSession().touch();
			}
			}catch(Exception e){
				response.sendRedirect("login.htm");						
				//e.printStackTrace();
				return false;
			}
		}
		return true;
	}
}
