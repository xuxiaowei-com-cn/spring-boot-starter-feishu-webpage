package org.springframework.security.oauth2.server.authorization.client;

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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.properties.FeiShuProperties;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * 飞书 账户服务接口
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see RegisteredClientRepository
 * @see InMemoryRegisteredClientRepository
 * @see JdbcRegisteredClientRepository
 */
public interface FeiShuService {

	/**
	 * 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID
	 * @param code 授权码，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param openid 用户唯一标识，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param credentials 证书
	 * @param unionid 多账户用户唯一标识，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param accessToken 授权凭证，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param refreshToken 刷新凭证，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param expiresIn 过期时间，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param scope {@link OAuth2ParameterNames#SCOPE}，授权范围，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn,
			String scope) throws OAuth2AuthenticationException;

	/**
	 * 根据 AppID、code、jsCode2SessionUrl 获取Token
	 * @param appid AppID，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param code 授权码，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @param accessTokenUrl <a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @return 返回 飞书授权结果
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	FeiShuTokenResponse getAccessTokenResponse(String appid, String code, String accessTokenUrl)
			throws OAuth2AuthenticationException;

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param feiShu 飞书配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse, FeiShuProperties.FeiShu feiShu)
			throws OAuth2AuthenticationException;

	/**
	 * 根据 appid 获取 飞书属性配置
	 * @param appid 飞书ID
	 * @return 返回 飞书属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	FeiShuProperties.FeiShu getFeiShuByAppid(String appid) throws OAuth2AuthenticationException;

	/**
	 * 获取 OAuth 2.1 授权 Token（如果不想执行此方法后面的内容，可返回 null）
	 * @param request 请求
	 * @param response 响应
	 * @param tokenUrlPrefix 获取 Token URL 前缀
	 * @param tokenUrl Token URL
	 * @param uriVariables 参数
	 * @return 返回 OAuth 2.1 授权 Token
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request, HttpServletResponse response,
			String tokenUrlPrefix, String tokenUrl, Map<String, String> uriVariables)
			throws OAuth2AuthenticationException;

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 飞书ID
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	String getRedirectUriByAppid(String appid);

}
