package com.pengjunlee.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/article")
public class ArticleController {
	
	/*
	@GetMapping("/delete")
	public String deleteArticle(ModelMap model) {
		// 获取当前用户
		Subject currentUser = SecurityUtils.getSubject();
		// 检查用户的角色
		if (currentUser.hasRole("admin")) {
			return "文章删除成功！";
		}
		return "尚未开通文章删除权限！";
	}

	@GetMapping("/read")
	public String readArticle(ModelMap model) {
		// 获取当前用户
		Subject currentUser = SecurityUtils.getSubject();
		// 检查用户的权限
		if (currentUser.isPermitted("article:read")) {
			return "请您鉴赏！";
		}
		return "尚未开通文章阅读权限！";
	}
	*/

	@GetMapping("/delete")
	@RequiresRoles(value = { "admin" })
	public String deleteArticle(ModelMap model) {
		return "文章删除成功！";
	}

	@GetMapping("/read")
	@RequiresPermissions(value = { "article:read" })
	public String readArticle(ModelMap model) {
		return "请您鉴赏！";
	}

}
