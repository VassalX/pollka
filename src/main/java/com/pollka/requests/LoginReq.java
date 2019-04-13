package com.pollka.requests;

import javax.validation.constraints.NotBlank;

public class LoginReq {
    @NotBlank
    private String usernmaeOrEmail;

    @NotBlank
    private String password;

    public String getUsernmaeOrEmail() {
        return usernmaeOrEmail;
    }

    public void setUsernmaeOrEmail(String usernmaeOrEmail) {
        this.usernmaeOrEmail = usernmaeOrEmail;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
