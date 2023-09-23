package com.jp.dev.commons.domain;

public class JwtData {

  public JwtData() {
  }

  private String sub;
  private String role;
  private long exp;

  public String getSub() {
    return sub;
  }

  public void setSub(String sub) {
    this.sub = sub;
  }

  public String getRole() {
    return role;
  }

  public void setRole(String role) {
    this.role = role;
  }

  public long getExp() {
    return exp;
  }

  public void setExp(long exp) {
    this.exp = exp;
  }
}
