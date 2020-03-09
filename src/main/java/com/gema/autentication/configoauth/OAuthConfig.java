package com.gema.autentication.configoauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "oauth")

public class OAuthConfig {
	private boolean enabled;
	private JWT jwt;
}
