package com.rs.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;

@Getter

@JsonInclude(JsonInclude.Include.NON_NULL)
public class APIResponse {
    private Message message;
    private Object response;
    private APIErrorResponse errorResponse;

    public APIResponse() {
    }

    public APIResponse(Message message, Object response) {
        this.message = message;
        this.response = response;
    }

    public APIResponse(Message message, APIErrorResponse errorResponse) {
        this.message = message;
        this.errorResponse = errorResponse;
    }

    public enum Message {
        SUCCESS, FAILED
    }


}
