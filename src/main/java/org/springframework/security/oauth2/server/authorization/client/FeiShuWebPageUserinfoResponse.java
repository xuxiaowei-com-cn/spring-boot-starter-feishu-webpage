package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;

/**
 * 获取用户信息
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see <a href=
 * "https://open.feishu.cn/document/common-capabilities/sso/api/get-user-info">获取用户信息</a>
 */
@Data
public class FeiShuWebPageUserinfoResponse implements Serializable {

	/**
	 * 用户在应用内的唯一标识，等同于open_id
	 */
	private String sub;

	/**
	 * 用户姓名
	 */
	private String name;

	/**
	 * 用户头像，等同于avatar_url
	 */
	private String picture;

	/**
	 * 用户在应用内的唯一标识, 等同于sub
	 */
	@JsonProperty("open_id")
	private String openId;

	/**
	 * 用户统一ID，在同一租户开发的所有应用内的唯一标识
	 */
	@JsonProperty("union_id")
	private String unionId;

	/**
	 * 用户英文名称
	 */
	@JsonProperty("en_name")
	private String enName;

	/**
	 * 当前企业标识
	 */
	@JsonProperty("tenant_key")
	private String tenantKey;

	/**
	 * 用户头像，等同于picture
	 */
	@JsonProperty("avatar_url")
	private String avatarUrl;

	/**
	 * 用户头像 72x72
	 */
	@JsonProperty("avatar_thumb")
	private String avatarThumb;

	/**
	 * 用户头像 240x240
	 */
	@JsonProperty("avatar_middle")
	private String avatarMiddle;

	/**
	 * 用户头像 640x640
	 */
	@JsonProperty("avatar_big")
	private String avatarBig;

	/**
	 * 用户 user id，申请了员工信息获取权限(获取用户 user ID)的应用会返回该字段【仅自建应用】
	 */
	@JsonProperty("user_id")
	private String userId;

	/**
	 * 用户工号，申请了员工信息获取权限(获取用户 user ID)的应用会返回该字段【仅自建应用】
	 */
	@JsonProperty("employee_no")
	private String employeeNo;

	/**
	 * 用户邮箱，申请了邮箱获取权限(获取用户邮箱信息)的应用会返回该字段
	 */
	@JsonProperty("email")
	private String email;

	/**
	 * 用户手机号，申请了手机号获取权限(获取用户手机号)的应用会返回该字段
	 */
	@JsonProperty("mobile")
	private String mobile;

}
