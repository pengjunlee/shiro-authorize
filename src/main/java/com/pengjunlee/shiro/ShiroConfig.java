package com.pengjunlee.shiro;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import net.sf.ehcache.CacheManager;

@Configuration
public class ShiroConfig {

	/**
	 * 交由 Spring 来自动地管理 Shiro-Bean 的生命周期
	 */
	@Bean
	public static LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}

	/**
	 * 为 Spring-Bean 开启对 Shiro 注解的支持
	 */
	@Bean
	public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
		AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
		authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
		return authorizationAttributeSourceAdvisor;
	}

	@Bean
	public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
		DefaultAdvisorAutoProxyCreator app = new DefaultAdvisorAutoProxyCreator();
		app.setProxyTargetClass(true);
		return app;

	}

	/**
	 * 配置访问资源需要的权限
	 */
	@Bean
	ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		shiroFilterFactoryBean.setLoginUrl("/login");
		shiroFilterFactoryBean.setSuccessUrl("/authorized");
		shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
		LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
		filterChainDefinitionMap.put("/login", "anon"); // 可匿名访问
		filterChainDefinitionMap.put("/logout", "logout"); // 退出登录
		filterChainDefinitionMap.put("/**", "authc"); // 需登录才能访问
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
		return shiroFilterFactoryBean;
	}

	/**
	 * 配置 ModularRealmAuthenticator
	 */
	@Bean
	public ModularRealmAuthenticator authenticator() {
		ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
		// 设置多 Realm的认证策略，默认 AtLeastOneSuccessfulStrategy
		AuthenticationStrategy strategy = new AtLeastOneSuccessfulStrategy();
		authenticator.setAuthenticationStrategy(strategy);
		return authenticator;
	}

	/**
	 * ShiroDialect 是为了在thymeleaf里使用shiro标签的bean
	 */
	@Bean
	public ShiroDialect shiroDialect() {
		return new ShiroDialect();
	}

	/**
	 * EhCacheManager缓存配置，默认使用 classpath:/ehcache.xml
	 */
	@Bean("cacheManager")
	public EhCacheManager ehCacheManager() {
		EhCacheManager em = new EhCacheManager();
		em.setCacheManager(cacheManager());
		return em;
	}

	@Bean("cacheManager2")
	CacheManager cacheManager() {
		return CacheManager.create();
	}

	/**
	 * Realm1 配置，需实现 Realm 接口
	 */
	@Bean
	LoginRealm loginRealm() {
		LoginRealm loginRealm = new LoginRealm();
		// 设置加密算法
		HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher("SHA-1");
		// 设置加密次数
		credentialsMatcher.setHashIterations(16);
		loginRealm.setCredentialsMatcher(credentialsMatcher);
		return loginRealm;
	}
	
	/**
	 * Realm2 配置，需实现 Realm 接口
	 */
	@Bean
	UserRealm userRealm() {
		UserRealm userRealm = new UserRealm();
		// 设置加密算法
		HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher("SHA-1");
		// 设置加密次数
		credentialsMatcher.setHashIterations(16);
		userRealm.setCredentialsMatcher(credentialsMatcher);
		return userRealm;
	}

	/**
	 * 使用 Session 第一步 创建 SessionDAO 的同时设置其 SessionIdGenerator 属性
	 */
	@Bean
	public SessionDAO sessionDAO() {
		EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
		// 设置 SessionIdGenerator
		sessionDAO.setSessionIdGenerator(new JavaUuidSessionIdGenerator());
		// 需要使用缓存时，设置 CacheManager
		EhCacheManager em = new EhCacheManager();
		em.setCacheManager(CacheManager.create());
		sessionDAO.setCacheManager(em);
		return sessionDAO;
	}

	/**
	 * 使用 Session 第二步 创建 SessionManager 的同时设置其 SessionDAO 属性
	 */
	@Bean
	public DefaultSessionManager sessionManager() {
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		sessionManager.setGlobalSessionTimeout(1800 * 1000);
		sessionManager.setDeleteInvalidSessions(true);
		sessionManager.setSessionValidationSchedulerEnabled(true);
		sessionManager.setSessionDAO(sessionDAO());
		return sessionManager;
	}

	/**
	 * 使用 Cookie 第一步 创建 SimpleCookie
	 */
	@Bean
	public SimpleCookie simpleCookie() {
		SimpleCookie simpleCookie = new SimpleCookie();
		simpleCookie.setName("shiro-cookies");
		simpleCookie.setHttpOnly(true);
		// 设置 Cookies 的过期时间
		simpleCookie.setMaxAge(60);
		return simpleCookie;
	}

	/**
	 * 使用 Cookie 第二步 创建 CookieRememberMeManager 的同时设置其 Cookie 属性
	 */
	@Bean
	public CookieRememberMeManager cookieRememberMeManager() {
		CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
		cookieRememberMeManager.setCipherKey(Base64.decode("4AvVhmFLUs0KTA3Kprsdag=="));
		cookieRememberMeManager.setCookie(simpleCookie());
		return cookieRememberMeManager;
	}

	/**
	 * 使用 Cookie 第三步 创建 SecurityManager 的同时设置其 CookieRememberMeManager 属性
	 */
	@Bean
	public SecurityManager securityManager() {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

		// 1.CacheManager
		securityManager.setCacheManager(ehCacheManager());

		// 2. Authenticator
		securityManager.setAuthenticator(authenticator());

		// 3.Realm
		List<Realm> realms = new ArrayList<Realm>(16);
		realms.add(loginRealm());
		realms.add(userRealm());
		securityManager.setRealms(realms);

		// 4.SessionManager
		securityManager.setSessionManager(sessionManager());

		// 5. CookieRememberMeManager
		securityManager.setRememberMeManager(cookieRememberMeManager());
		return securityManager;
	}
}
