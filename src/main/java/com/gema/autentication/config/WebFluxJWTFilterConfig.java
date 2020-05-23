package com.gema.autentication.config;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.gema.autentication.configoauth.MatcherConfigure;
import com.gema.autentication.configoauth.OAuthConfig;

import reactor.core.publisher.Mono;

@Configuration
@ConditionalOnProperty(prefix = "oauth", name = "enabled", havingValue = "true", matchIfMissing = false)
public class WebFluxJWTFilterConfig implements WebFilter {
	Logger log = LoggerFactory.getLogger(this.getClass());
	@Autowired
	private OAuthConfig oauthConfig;

	public Mono<Void> processSecurityClient(ServerWebExchange exchange, WebFilterChain chain) {
		log.error(oauthConfig.toString());
		Mono<Void> response = null;
		String token = exchange.getRequest().getHeaders().getFirst("Authorization");
		String path = exchange.getRequest().getPath().toString();
		String method = exchange.getRequest().getMethod().name();
		boolean isValid = false;
		if (Objects.nonNull(oauthConfig.getJwt().getExcludeMatchers())) {
			isValid = existPath(oauthConfig.getJwt().getExcludeMatchers(), path, method, token, false);
		}
		if (!isValid && Objects.nonNull(oauthConfig.getJwt().getMatchersWithRole()) && Objects.nonNull(token)) {
			isValid = existPath(oauthConfig.getJwt().getMatchersWithRole(), path, method, token, true);
		}
		if (isValid) {
			response = chain.filter(exchange);
		} else {
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			chain.filter(exchange);
			response = Mono.empty();
		}
		return response;
	}

	private boolean existPath(List<MatcherConfigure> matchers, String path, String method, String token,
			boolean validateToken) {
		boolean isValid = false;
		int i = 0;
		while (i < matchers.size() && !isValid) {
			MatcherConfigure matcher = matchers.get(i);
			if (method.equals(matcher.getMethod().name())) {
				int y = 0;
				while (y < matcher.getPaths().length && !isValid) {
					String valuePath = matcher.getPaths()[y];
					if (path.matches(valuePath)) {
						if (validateToken) {
							isValid = isValidToken(token, matcher.getRoles());
						} else {
							isValid = true;
						}
					}
					y++;
				}
			}
			i++;
		}
		return isValid;
	}


	private boolean isValidToken(String token, String... roles) {
		boolean isValid = false;
		try {
			Algorithm algorithm = Algorithm.HMAC256(oauthConfig.getJwt().getPassword());
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(oauthConfig.getJwt().getIssuer()).build();
			DecodedJWT jwt = verifier.verify(token.split("\\s")[1]);
			List<String> rol = jwt.getClaim("roles").asList(String.class);
			Map<String, String> mapRols = rol.stream().collect(Collectors.toMap(x -> x, x -> x));
			if (Objects.nonNull(roles)) {
				for (String r : roles) {
					if (mapRols.containsKey(r)) {
						isValid = true;
					}
				}
			}
			if (!isValid) {
				log.error("No tiene la autoridad para consumir el servicio");
			}
		} catch (JWTVerificationException exception) {
			log.error("No funciono el token:" + exception.getMessage());
		}
		return isValid;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return processSecurityClient(exchange, chain);
	}

}
