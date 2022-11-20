# keycloak-validate-otp-conditional

This plugin brings Conditional OTP to the Direct Grant.

Mix between native plugins:
- [keycloak/keycloak/services/src/main/java/org/keycloak/authentication/authenticators/directgrant/ValidateOTP.java](https://github.com/keycloak/keycloak/blob/bfce612641a70e106b20b136431f0e4046b5c37f/services/src/main/java/org/keycloak/authentication/authenticators/directgrant/ValidateOTP.java)
- [keycloak/keycloak/services/src/main/java/org/keycloak/authentication/authenticators/browser/ConditionalOtpFormAuthenticator.java](https://github.com/keycloak/keycloak/blob/bfce612641a70e106b20b136431f0e4046b5c37f/services/src/main/java/org/keycloak/authentication/authenticators/browser/ConditionalOtpFormAuthenticator.java)

Inspired by: https://github.com/lukaszbudnik/keycloak-ip-authenticator

Use case:

- When IP whitelisting passes, set user attribute: `ip_based_otp_conditional=skip` else`ip_based_otp_conditional=force`
- Configure this module to be conditional on this user attribute (OTP control User Attribute)

Also see our extended version of [keycloak-ip-authenticator](https://github.com/Nextpertise/keycloak-ip-authenticator).