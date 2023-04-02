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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;

/**
 * 通过 code 换取网页授权 access_token 返回值
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see <a href=
 * "https://open.feishu.cn/document/common-capabilities/sso/web-application-sso/web-app-overview">登录流程</a>
 */
@Data
public class FeiShuWebPageTokenResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * 飞书服务器授权的access_token，用于调用其他接口
	 */
	@JsonProperty("access_token")
	private String accessToken;

	/**
	 * OAuth 2.0协议规定的Token类型，固定为 Bearer
	 */
	@JsonProperty("token_type")
	private String tokenType;

	/**
	 * access_token 的有效期，三方应用服务器需要根据此返回值来控制access_token的有效时间
	 */
	@JsonProperty("expires_in")
	private Integer expiresIn;

	/**
	 * 当 access_token 过期时，通过 refresh_token来刷新，获取新的 access_token
	 */
	@JsonProperty("refresh_token")
	private String refreshToken;

	/**
	 * refresh_token 的有效期
	 */
	@JsonProperty("refresh_expires_in")
	private Integer refreshExpiresIn;

	/**
	 * 获取用户信息
	 */
	private FeiShuWebPageUserinfoResponse userinfo;

}
