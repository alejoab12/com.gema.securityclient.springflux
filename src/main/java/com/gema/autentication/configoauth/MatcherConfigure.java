package com.gema.autentication.configoauth;

import org.springframework.http.HttpMethod;

import lombok.Data;
@Data
public class MatcherConfigure {
	private HttpMethod method;
	private String[] paths;
	private String[] roles;
}
