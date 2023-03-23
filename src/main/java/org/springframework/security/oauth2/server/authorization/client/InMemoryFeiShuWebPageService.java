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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.FeiShuWebPageAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidFeiShuWebPageException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectFeiShuWebPageException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriFeiShuWebPageException;
import org.springframework.security.oauth2.server.authorization.properties.FeiShuWebPageProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2FeiShuWebPageEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestTemplateFeiShuWebPage;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 飞书 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
public class InMemoryFeiShuWebPageService implements FeiShuWebPageService {

	private final FeiShuWebPageProperties feiShuWebPageProperties;

	public InMemoryFeiShuWebPageService(FeiShuWebPageProperties feiShuWebPageProperties) {
		this.feiShuWebPageProperties = feiShuWebPageProperties;
	}

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
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(feiShuWebPageProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(openid, accessToken, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		FeiShuWebPageAuthenticationToken authenticationToken = new FeiShuWebPageAuthenticationToken(authorities,
				clientPrincipal, principal, user, additionalParameters, details, appid, code, openid);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setUnionid(unionid);

		return authenticationToken;
	}

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
	@Override
	public FeiShuWebPageTokenResponse getAccessTokenResponse(String appid, String code, String accessTokenUrl) {
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();

		String secret = getSecretByAppid(appid);
		String redirectUri = getRedirectUriByAppid(appid);

		body.put(OAuth2ParameterNames.CLIENT_ID, Collections.singletonList(appid));
		body.put(OAuth2ParameterNames.CLIENT_SECRET, Collections.singletonList(secret));
		body.put(OAuth2ParameterNames.CODE, Collections.singletonList(code));
		body.put(OAuth2ParameterNames.GRANT_TYPE,
				Collections.singletonList(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
		body.put(OAuth2ParameterNames.REDIRECT_URI, Collections.singletonList(redirectUri));

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(body, httpHeaders);

		String forObject = restTemplate.postForObject(accessTokenUrl, httpEntity, String.class);

		FeiShuWebPageTokenResponse feiShuWebPageTokenResponse;
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		try {
			feiShuWebPageTokenResponse = objectMapper.readValue(forObject, FeiShuWebPageTokenResponse.class);
		}
		catch (JsonProcessingException e) {
			OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE,
					"使用飞书授权code：" + code + " 获取Token异常", OAuth2FeiShuWebPageEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		String accessToken = feiShuWebPageTokenResponse.getAccessToken();
		if (accessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE, "飞书授权失败",
					OAuth2FeiShuWebPageEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		return feiShuWebPageTokenResponse;
	}

	/**
	 * 获取授权用户的资料
	 * @param userinfoUrl 用户信息接口
	 * @param appid AppID(飞书Gitee client_id)
	 * @param state 状态码
	 * @param binding 是否绑定，需要使用者自己去拓展
	 * @param remoteAddress 用户IP
	 * @param sessionId SessionID
	 * @param feiShuWebPageTokenResponse 飞书 Token
	 * @see <a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/api/get-user-info">获取用户信息</a>
	 * @return 返回授权用户的资料
	 */
	@Override
	public FeiShuWebPageUserinfoResponse getUserInfo(String userinfoUrl, String appid, String state, String binding,
			String remoteAddress, String sessionId, FeiShuWebPageTokenResponse feiShuWebPageTokenResponse) {
		String accessToken = feiShuWebPageTokenResponse.getAccessToken();

		RestTemplateFeiShuWebPage restTemplate = new RestTemplateFeiShuWebPage();
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		httpHeaders.setBearerAuth(accessToken);
		HttpEntity<HttpHeaders> httpEntity = new HttpEntity<>(httpHeaders);

		FeiShuWebPageUserinfoResponse feiShuWebPageUserinfoResponse;
		try {
			feiShuWebPageUserinfoResponse = restTemplate.getForObject(userinfoUrl, httpEntity,
					FeiShuWebPageUserinfoResponse.class);
		}
		catch (Exception e) {
			OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE,
					"使用Token：" + accessToken + " 获取用户信息异常", OAuth2FeiShuWebPageEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		if (feiShuWebPageUserinfoResponse == null) {
			OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE,
					"使用Token：" + accessToken + " 获取用户信息异常", OAuth2FeiShuWebPageEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		return feiShuWebPageUserinfoResponse;
	}

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param feiShuWebPage 飞书配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse, FeiShuWebPageProperties.FeiShuWebPage feiShuWebPage) {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(feiShuWebPage.getSuccessUrl() + "?" + feiShuWebPage.getParameterName() + "="
					+ accessToken.getTokenValue());
		}
		catch (IOException e) {
			OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE, "飞书重定向异常", null);
			throw new RedirectFeiShuWebPageException(error, e);
		}
	}

	/**
	 * 根据 appid 获取 飞书属性配置
	 * @param appid 飞书ID
	 * @return 返回 飞书属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public FeiShuWebPageProperties.FeiShuWebPage getFeiShuWebPageByAppid(String appid) {
		List<FeiShuWebPageProperties.FeiShuWebPage> list = feiShuWebPageProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE, "appid 未配置", null);
			throw new AppidFeiShuWebPageException(error);
		}

		for (FeiShuWebPageProperties.FeiShuWebPage feiShuWebPage : list) {
			if (appid.equals(feiShuWebPage.getAppid())) {
				return feiShuWebPage;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidFeiShuWebPageException(error);
	}

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
	@Override
	public OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request,
			HttpServletResponse response, String tokenUrlPrefix, String tokenUrl, Map<String, String> uriVariables)
			throws OAuth2AuthenticationException {

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

		RestTemplate restTemplate = new RestTemplate();

		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		messageConverters.add(5, new OAuth2AccessTokenResponseHttpMessageConverter());

		return restTemplate.postForObject(tokenUrlPrefix + tokenUrl, httpEntity, OAuth2AccessTokenResponse.class,
				uriVariables);
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 飞书ID
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public String getRedirectUriByAppid(String appid) throws OAuth2AuthenticationException {
		FeiShuWebPageProperties.FeiShuWebPage feiShuWebPage = getFeiShuWebPageByAppid(appid);
		String redirectUriPrefix = feiShuWebPage.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return redirectUriPrefix + "/" + appid;
		}
		else {
			OAuth2Error error = new OAuth2Error(OAuth2FeiShuWebPageEndpointUtils.ERROR_CODE, "重定向地址前缀不能为空", null);
			throw new RedirectUriFeiShuWebPageException(error);
		}
	}

	/**
	 * 根据 AppID 查询 AppSecret
	 * @param appid AppID，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 * @return 返回 AppSecret，<a href=
	 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
	 */
	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		FeiShuWebPageProperties.FeiShuWebPage feiShuWebPage = getFeiShuWebPageByAppid(appid);
		return feiShuWebPage.getSecret();
	}

}
