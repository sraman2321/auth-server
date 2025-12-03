package com.rs.auth.dto;

import java.util.List;

public record ClientRegisterRequest(
        String clientId,
        String clientSecret,
        List<String> scopes,
        List<String> grantTypes
) {
}
