package com.fsa.auth;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordService;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.util.JdbcUtils;

public class JNDIJdbcRelam extends JdbcRealm{
	static private final Logger log = Logger.getLogger(JNDIJdbcRelam.class);
	
	protected String jndiDataSourceName;

	public JNDIJdbcRelam() {
	}

	public String getJndiDataSourceName() {
		return jndiDataSourceName;
	}

	//protected String jndiDataSourceName = "java:comp/env/jdbc/fsaApplicationDB";

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		UsernamePasswordToken userPassToken = (UsernamePasswordToken) token;
		String username = userPassToken.getUsername();
		char[] passwordAuth = userPassToken.getPassword();
		String usrpwd = String.valueOf(passwordAuth).trim();
		
		if (username.isEmpty() || username==null) {
			log.info("User Name is Null");
			return null;
		}
		
		String password = getPasswordForUser(username,usrpwd);
		if (password == null) {	
			log.info("Password is Null");
			return null;
		}
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(username,usrpwd,getName());
		return info;
	}
	
	private String getPasswordForUser(String username,String userPassword){
		log.info("Executing getPasswordForUser.........");
		PreparedStatement statement = null;
		ResultSet resultSet = null;
		Connection conn = null;
		String password = null;
		Integer status = null;
		try {
			log.info("AuthenticationQuery....."+authenticationQuery);
			
			InitialContext context = new InitialContext();
			dataSource = (DataSource) context.lookup("java:comp/env/jdbc/fsaApplicationDBlocal");
			conn = dataSource.getConnection();
			statement = conn.prepareStatement(authenticationQuery);
			statement.setString(1, username);

			resultSet = statement.executeQuery();
			if(resultSet.next()){
				 password = resultSet.getString(1);
				 status = resultSet.getInt(2);				 
			}
			if((password != null || password != "") && status!=0){
				PasswordService ps = new DefaultPasswordService();
				if(ps.passwordsMatch(userPassword, password)){
					log.info("isAuthenticated successFully");
					return password;
				}
			}
				
		} catch (SQLException e) {
			log.info(e);
			e.printStackTrace();
			
		} catch (NamingException e) {
			log.info(e);
			e.printStackTrace();
		} finally {
			JdbcUtils.closeResultSet(resultSet);
			JdbcUtils.closeStatement(statement);
			JdbcUtils.closeConnection(conn);
		}
		return null;
	}
}


