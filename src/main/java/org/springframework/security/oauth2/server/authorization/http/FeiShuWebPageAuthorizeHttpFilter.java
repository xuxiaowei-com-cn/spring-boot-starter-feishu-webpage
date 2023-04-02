package org.springframework.security.oauth2.server.authorization.http;

/*-
 * #%L
 * spring-boot-starter-feishu-webpage
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2FeiShuWebPageParameterNames;
import org.springframework.security.oauth2.server.authorization.client.FeiShuWebPageService;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;

/**
 * 飞书跳转到飞书授权页面
 *
 * @see <a href=
 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class FeiShuWebPageAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/feishu-webpage/authorize";

	/**
	 * @see <a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 */
	public static final String AUTHORIZE_URL = "https://passport.feishu.cn/suite/passport/oauth/authorize"
			+ "?client_id=%s&redirect_uri=%s&response_type=code&state=%s";

	private FeiShuWebPageService feiShuWebPageService;

	@Autowired
	public void setFeiShuWebPageService(FeiShuWebPageService feiShuWebPageService) {
		this.feiShuWebPageService = feiShuWebPageService;
	}

	/**
	 * 飞书授权前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");

			String redirectUri = feiShuWebPageService.getRedirectUriByAppid(appid);

			String binding = request.getParameter(OAuth2FeiShuWebPageParameterNames.BINDING);

			String state = feiShuWebPageService.stateGenerate(request, response, appid);
			feiShuWebPageService.storeBinding(request, response, appid, state, binding);
			feiShuWebPageService.storeUsers(request, response, appid, state, binding);

			String url = String.format(AUTHORIZE_URL, appid, redirectUri, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
