package com.fsa.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordService;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.fsa.archive.Util;
import com.fsa.db.User;
import com.fsa.db.Message;
import com.fsa.services.MailService;
import com.fsa.services.RoleService;
import com.fsa.services.UserService;

@Controller
public class LoginController {
	static private final Logger log = Logger.getLogger(LoginController.class);
	
	@Resource
	UserService userService;
	
	@Resource
	MailService mailservice;
	
	@Resource
	RoleService roleService;
	
	@Resource
	Message validation;
	
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public ModelAndView loign(ModelMap model) {	
		model.addAttribute("errorMsg", "");
		model.addAttribute("messages", validation);
			return new ModelAndView("login");
	}
	
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public ModelAndView validateUser(@RequestParam("email") String email,@RequestParam("password") String password,
			HttpServletRequest request, ModelMap model) {
		model.addAttribute("messages", validation);
			if(email==null || password==null || email.isEmpty() || password.isEmpty()){
				model.addAttribute("errorMsg", validation.getInvalidCredentialsMsg());
				return new ModelAndView("login");
			}
		Authentication auth = new Authentication();
		Subject subject = null;
		Session session = null;
		try {
			subject = auth
					.userAuthenticate(email, password);
		} catch (IncorrectCredentialsException e) {
			model.addAttribute("errorMsg", validation.getInvalidCredentialsMsg());
			return new ModelAndView("login");
		}
		if (subject != null && subject.isAuthenticated()) {
			session = subject.getSession();
			session.setTimeout(900000);
			request.getSession().setAttribute("currentUser", subject);
			
			log.info("Shiro subject Successfully Loaded");	
			User user = userService.getEmail(email);
			request.getSession().setAttribute("userId", user.getUserId());
			request.getSession().setAttribute("role", user.getRoleId().toString());
			String userFullNames = Util.userFullName("",
					user.getFirstName()+",", user.getLastName());
			request.getSession().setAttribute("userName", userFullNames);
			Map<String, String>  menuMap = new HashMap<>();
			menuMap = roleService.getRoleMenus(user.getRoleId());
			if(subject.hasRole("Admin")){
				ModelAndView modelAndView = new ModelAndView("redirect:user.htm");
				modelAndView.addObject("searchText", "");
				modelAndView.addObject("number-of-pages", "10");
				return modelAndView;
			}else if(subject.hasRole("User")){
				ModelAndView modelAndView = new ModelAndView("redirect:report.htm");
				return modelAndView;
			}
		}
			model.addAttribute("errorMsg", validation.getInvalidCredentialsMsg());
			return new ModelAndView("login");
	}


	@RequestMapping(value = "/logOut.htm", method = RequestMethod.POST)
	public ModelAndView logout(HttpServletRequest request) {		
		log.info("********* Logout *********");
		try {
			Subject sub = (Subject) request.getSession().getAttribute("currentUser");
			sub.logout();
		} catch (UnknownSessionException e) {
			return new ModelAndView("redirect:login.htm");
		}catch (Exception e) {
			return new ModelAndView("redirect:login.htm");
		}
		return new ModelAndView("redirect:login.htm");
	}
	
	@RequestMapping(value = "/recoverPasswordMail.htm", method = RequestMethod.POST)
	public ModelAndView recoverPassword(@RequestParam("eMail") String eMail,
			HttpServletRequest request,ModelMap model) {
		try {
			log.info("recoverPasswordMail");
			log.info(" Recover Password Mail Address Is : " + eMail);
			User user = userService.getEmail(eMail);
			if (user != null && !eMail.isEmpty()) {
				User userPassword = new User();
				userPassword = user;
				userPassword.setIsTokenExpired(1);
				userPassword.setSecurityToken(UUID.randomUUID().toString());
				String securityToken = userService
						.resetPasswordLink(userPassword);
				log.info("Random Id  " + securityToken);
				String title = (String) userService.listTitle().get(user.getTitle());
				String userFullName=Util.userFullName(title+".", user.getFirstName(), user.getLastName());
				mailservice.sendSecurtityToken(userFullName,eMail,Util.securityTokenUrlGeneration(request, securityToken));
				log.info(" Forget Password URL : " + securityToken);
				model.addAttribute("errorMsg", "successLink");
			} else{
				model.addAttribute("errorMsg", "error");
				log.error("Invalid eMail Address " + eMail);
			}
		} catch (Exception e) {
			log.error("Exception occurred while get the user detail(LoginController)"
					+ e.getMessage());
		}
		model.addAttribute("messages", validation);
		return new ModelAndView("passwordLink");
	}
	@RequestMapping(value="{randomId}/passWordAuthentcation.htm", method= RequestMethod.GET)
	private ModelAndView changePassword(@PathVariable String randomId,HttpServletRequest request,ModelMap model) {
		log.info(" Forget Password");
		String action = "";
		ModelAndView modelAndView = null;
		String emailStr=null;
		Integer notExpiry=null;
		try{
			log.info(" Random Id Changed : " + randomId);
			User user = userService.changePassword(randomId);
			if(user!=null){
				 notExpiry = user.getIsTokenExpired();
			}
			if(user!=null && notExpiry!=null && notExpiry==1){
				emailStr =user.getEmail();
				action = "forgetPassword";
			}else{
				log.info("Your forgot password link session has been expired");
				model.addAttribute("errorMsg", "linkExpired");
				model.addAttribute("appUrl", Util.generateUrl(request));
				action = "changePasswordConfirmation";
			}
			modelAndView  = new ModelAndView(action);
			modelAndView.addObject("email", emailStr);
		}catch(Exception e){
			log.error("Exception occurred while get the user (LoginController)" +e);
		}
		model.addAttribute("messages", validation);
		return modelAndView;
	}
	@RequestMapping(value="{randomId}/passwordChanged.htm", method= RequestMethod.POST)
	public ModelAndView confirmPassword(@PathVariable String randomId,@RequestParam("eMail") String eMail,@RequestParam("newPassword") String newPassword, 
			@RequestParam("confirmPassword") String confirmPassword,HttpServletRequest request,ModelMap model){
		ModelAndView modelAndView =null;
		String emailStr=eMail;
		try{
			log.info(" EMail Address Is : "+eMail);
			if(newPassword.isEmpty() || confirmPassword.isEmpty() ){
				log.info("Password(s) is empty ");
				model.addAttribute("forgetError",validation.getPasswordsRequiredMsg());
				modelAndView = new ModelAndView("forgetPassword");
				modelAndView.addObject("email", emailStr);
				return modelAndView;
			}
			if(newPassword.length()<6 || confirmPassword.length()<6){
				log.info("Password length is less than 6");
				model.addAttribute("forgetError",validation.getIncorrectPasswordLengthMsg());
				modelAndView = new ModelAndView("forgetPassword");
				modelAndView.addObject("email", emailStr);
				return modelAndView;
			}
			User user = userService.getEmail(eMail);
			if(user!= null){
				PasswordService ps = new DefaultPasswordService();
				User updatePassword = new User();
				if(newPassword.equals(confirmPassword)){
					updatePassword = user;
					updatePassword.setPassword(ps.encryptPassword(newPassword));
					updatePassword.setIsTokenExpired(0);
					userService.resetPasswordLink(updatePassword);
					model.addAttribute("errorMsg","passwordSuccess");
					model.addAttribute("messages", validation);
					model.addAttribute("appUrl", Util.generateUrl(request));
					modelAndView = new ModelAndView("changePasswordConfirmation");
				}else
				{
					model.addAttribute("forgetError", "Password does not match");
					modelAndView = new ModelAndView("forgetPassword");
					modelAndView.addObject("email", emailStr);
					log.error("Password does not match ");
				}
			}else{
				log.info("Invalid email for create forget password");
				model.addAttribute("forgetError", "Invalid email address");
				model.addAttribute("messages", validation);
				modelAndView = new ModelAndView("forgetPassword");
				modelAndView.addObject("email", emailStr);
			}
		}catch(Exception e){
			log.error("Exception occurred while get the user detail(LoginController)" +e.getMessage());
		}
		model.addAttribute("messages", validation);
		return modelAndView;
	}
}
