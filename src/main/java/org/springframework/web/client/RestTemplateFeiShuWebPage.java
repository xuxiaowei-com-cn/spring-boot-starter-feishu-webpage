package org.springframework.web.client;

import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.Map;

/**
 * 重写 {@link RestTemplate}，使 {@link HttpMethod#GET} 支持设置 Header
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RestTemplateFeiShuWebPage extends RestTemplate {

	/**
	 * @see RestTemplate#postForObject(String, Object, Class, Map)
	 */
	@Nullable
	public <T> T getForObject(String url, @Nullable Object request, Class<T> responseType, Map<String, ?> uriVariables)
			throws RestClientException {
		RequestCallback requestCallback = httpEntityCallback(request, responseType);
		HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor<>(responseType,
				getMessageConverters(), logger);
		return execute(url, HttpMethod.GET, requestCallback, responseExtractor, uriVariables);
	}

	/**
	 * @see RestTemplate#postForObject(URI, Object, Class)
	 */
	@Nullable
	public <T> T getForObject(URI url, @Nullable Object request, Class<T> responseType) throws RestClientException {
		RequestCallback requestCallback = httpEntityCallback(request, responseType);
		HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor<>(responseType,
				getMessageConverters());
		return execute(url, HttpMethod.GET, requestCallback, responseExtractor);
	}

	/**
	 * @see RestTemplate#postForObject(String, Object, Class, Object...)
	 */
	@Nullable
	public <T> T getForObject(String url, @Nullable Object request, Class<T> responseType, Object... uriVariables)
			throws RestClientException {
		RequestCallback requestCallback = httpEntityCallback(request, responseType);
		HttpMessageConverterExtractor<T> responseExtractor = new HttpMessageConverterExtractor<>(responseType,
				getMessageConverters(), logger);
		return execute(url, HttpMethod.GET, requestCallback, responseExtractor, uriVariables);
	}

	/**
	 * @see RestTemplate#postForEntity(String, Object, Class, Map)
	 */
	public <T> ResponseEntity<T> getForEntity(String url, @Nullable Object request, Class<T> responseType,
			Map<String, ?> uriVariables) throws RestClientException {

		RequestCallback requestCallback = httpEntityCallback(request, responseType);
		ResponseExtractor<ResponseEntity<T>> responseExtractor = responseEntityExtractor(responseType);
		return nonNull(execute(url, HttpMethod.GET, requestCallback, responseExtractor, uriVariables));
	}

	/**
	 * @see RestTemplate#postForEntity(URI, Object, Class)
	 */
	public <T> ResponseEntity<T> getForEntity(URI url, @Nullable Object request, Class<T> responseType)
			throws RestClientException {

		RequestCallback requestCallback = httpEntityCallback(request, responseType);
		ResponseExtractor<ResponseEntity<T>> responseExtractor = responseEntityExtractor(responseType);
		return nonNull(execute(url, HttpMethod.GET, requestCallback, responseExtractor));
	}

	/**
	 * @see RestTemplate#postForEntity(String, Object, Class, Object...)
	 */
	public <T> ResponseEntity<T> getForEntity(String url, @Nullable Object request, Class<T> responseType,
			Object... uriVariables) throws RestClientException {

		RequestCallback requestCallback = httpEntityCallback(request, responseType);
		ResponseExtractor<ResponseEntity<T>> responseExtractor = responseEntityExtractor(responseType);
		return nonNull(execute(url, HttpMethod.GET, requestCallback, responseExtractor, uriVariables));
	}

	private static <T> T nonNull(@Nullable T result) {
		Assert.state(result != null, "No result");
		return result;
	}

}
