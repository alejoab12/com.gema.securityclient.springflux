package com.gema.autentication.configoauth;

import java.util.List;

import lombok.Data;

@Data
public class JWT {
	private String password;
	private List<MatcherConfigure> matchersWithRole;
	private List<MatcherConfigure> excludeMatchers;
	private Integer timeValidToken;
	private String issuer;
}
