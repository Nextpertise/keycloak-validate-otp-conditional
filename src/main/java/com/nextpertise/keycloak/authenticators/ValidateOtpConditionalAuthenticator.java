package com.nextpertise.keycloak.authenticators;

/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.keycloak.authentication.*;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.utils.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.nextpertise.keycloak.authenticators.ValidateOtpConditionalAuthenticator.OtpDecision.ABSTAIN;
import static com.nextpertise.keycloak.authenticators.ValidateOtpConditionalAuthenticator.OtpDecision.VALIDATE_OTP;
import static com.nextpertise.keycloak.authenticators.ValidateOtpConditionalAuthenticator.OtpDecision.SKIP_OTP;
import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ValidateOtpConditionalAuthenticator implements Authenticator, CredentialValidator<OTPCredentialProvider> {
//    public static final ValidateOtpConditionalAuthenticator SINGLETON = new ValidateOtpConditionalAuthenticator();
//    public static final String PROVIDER_ID = "direct-grant-validate-otp-conditional";

    public static final String SKIP = "skip";

    public static final String FORCE = "force";

    public static final String OTP_CONTROL_USER_ATTRIBUTE = "otpControlAttribute";

    public static final String SKIP_OTP_ROLE = "skipOtpRole";

    public static final String FORCE_OTP_ROLE = "forceOtpRole";

    public static final String SKIP_OTP_FOR_HTTP_HEADER = "noOtpRequiredForHeaderPattern";

    public static final String FORCE_OTP_FOR_HTTP_HEADER = "forceOtpForHeaderPattern";

    public static final String DEFAULT_OTP_OUTCOME = "defaultOtpOutcome";

    enum OtpDecision {
        SKIP_OTP, VALIDATE_OTP, ABSTAIN
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();

        if (tryConcludeBasedOn(voteForUserOtpControlAttribute(context.getUser(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForUserRole(context.getRealm(), context.getUser(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForHttpHeaderMatchesPattern(context.getHttpRequest().getHttpHeaders().getRequestHeaders(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForDefaultFallback(config), context)) {
            return;
        }
    }

    private void validateOtp(AuthenticationFlowContext context) {
        if (!configuredFor(context.getSession(), context.getRealm(), context.getUser())) {
            if (context.getExecution().isConditional()) {
                context.attempted();
            } else if (context.getExecution().isRequired()) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            }
            return;
        }
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        String otp = inputData.getFirst("otp");

        // KEYCLOAK-12908 Backwards compatibility. If parameter "otp" is null, then assign "totp".
        otp = (otp == null) ? inputData.getFirst("totp") : otp;

        // Always use default OTP credential in case of direct grant authentication
        String credentialId = getCredentialProvider(context.getSession())
                .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser()).getId();

        if (otp == null) {
            if (context.getUser() != null) {
                context.getEvent().user(context.getUser());
            }
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        boolean valid = getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), new UserCredentialModel(credentialId, OTPCredentialModel.TYPE, otp));
        if (!valid) {
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        context.success();
    }

    private OtpDecision voteForDefaultFallback(Map<String, String> config) {

        if (!config.containsKey(DEFAULT_OTP_OUTCOME)) {
            return ABSTAIN;
        }

        switch (config.get(DEFAULT_OTP_OUTCOME)) {
            case SKIP:
                return SKIP_OTP;
            case FORCE:
                return VALIDATE_OTP;
            default:
                return ABSTAIN;
        }
    }

    private boolean tryConcludeBasedOn(OtpDecision state, AuthenticationFlowContext context) {

        switch (state) {

            case VALIDATE_OTP:
                validateOtp(context);
                return true;

            case SKIP_OTP:
                context.success();
                return true;

            default:
                return false;
        }
    }

    private boolean tryConcludeBasedOn(OtpDecision state) {

        switch (state) {

            case VALIDATE_OTP:
                return true;

            case SKIP_OTP:
                return false;

            default:
                return false;
        }
    }

    private OtpDecision voteForUserOtpControlAttribute(UserModel user, Map<String, String> config) {

        if (!config.containsKey(OTP_CONTROL_USER_ATTRIBUTE)) {
            return ABSTAIN;
        }

        String attributeName = config.get(OTP_CONTROL_USER_ATTRIBUTE);
        if (attributeName == null) {
            return ABSTAIN;
        }

        Optional<String> value = user.getAttributeStream(attributeName).findFirst();
        if (!value.isPresent()) {
            return ABSTAIN;
        }

        switch (value.get().trim()) {
            case SKIP:
                return SKIP_OTP;
            case FORCE:
                return VALIDATE_OTP;
            default:
                return ABSTAIN;
        }
    }

    private OtpDecision voteForHttpHeaderMatchesPattern(MultivaluedMap<String, String> requestHeaders, Map<String, String> config) {

        if (!config.containsKey(FORCE_OTP_FOR_HTTP_HEADER) && !config.containsKey(SKIP_OTP_FOR_HTTP_HEADER)) {
            return ABSTAIN;
        }

        //Inverted to allow white-lists, e.g. for specifying trusted remote hosts: X-Forwarded-Host: (1.2.3.4|1.2.3.5)
        if (containsMatchingRequestHeader(requestHeaders, config.get(SKIP_OTP_FOR_HTTP_HEADER))) {
            return SKIP_OTP;
        }

        if (containsMatchingRequestHeader(requestHeaders, config.get(FORCE_OTP_FOR_HTTP_HEADER))) {
            return VALIDATE_OTP;
        }

        return ABSTAIN;
    }

    private boolean containsMatchingRequestHeader(MultivaluedMap<String, String> requestHeaders, String headerPattern) {

        if (headerPattern == null) {
            return false;
        }

        //TODO cache RequestHeader Patterns
        //TODO how to deal with pattern syntax exceptions?
        // need CASE_INSENSITIVE flag so that we also have matches when the underlying container use a different case than what
        // is usually expected (e.g.: vertx)
        Pattern pattern = Pattern.compile(headerPattern, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {

            String key = entry.getKey();

            for (String value : entry.getValue()) {

                String headerEntry = key.trim() + ": " + value.trim();

                if (pattern.matcher(headerEntry).matches()) {
                    return true;
                }
            }
        }

        return false;
    }

    private OtpDecision voteForUserRole(RealmModel realm, UserModel user, Map<String, String> config) {

        if (!config.containsKey(SKIP_OTP_ROLE) && !config.containsKey(FORCE_OTP_ROLE)) {
            return ABSTAIN;
        }

        if (userHasRole(realm, user, config.get(SKIP_OTP_ROLE))) {
            return SKIP_OTP;
        }

        if (userHasRole(realm, user, config.get(FORCE_OTP_ROLE))) {
            return VALIDATE_OTP;
        }

        return ABSTAIN;
    }

    private boolean userHasRole(RealmModel realm, UserModel user, String roleName) {

        if (roleName == null) {
            return false;
        }

        RoleModel role = getRoleFromString(realm, roleName);
        if (role != null) {
            return user.hasRole(role);
        }
        return false;
    }

    private boolean isOTPRequired(KeycloakSession session, RealmModel realm, UserModel user) {
        MultivaluedMap<String, String> requestHeaders = session.getContext().getRequestHeaders().getRequestHeaders();
        return realm.getAuthenticatorConfigsStream().anyMatch(configModel -> {
            if (tryConcludeBasedOn(voteForUserOtpControlAttribute(user, configModel.getConfig()))) {
                return true;
            }
            if (tryConcludeBasedOn(voteForUserRole(realm, user, configModel.getConfig()))) {
                return true;
            }
            if (tryConcludeBasedOn(voteForHttpHeaderMatchesPattern(requestHeaders, configModel.getConfig()))) {
                return true;
            }
            if (configModel.getConfig().get(DEFAULT_OTP_OUTCOME) != null
                    && configModel.getConfig().get(DEFAULT_OTP_OUTCOME).equals(FORCE)
                    && configModel.getConfig().size() <= 1) {
                return true;
            }
            if (containsConditionalOtpConfig(configModel.getConfig())
                    && voteForUserOtpControlAttribute(user, configModel.getConfig()) == ABSTAIN
                    && voteForUserRole(realm, user, configModel.getConfig()) == ABSTAIN
                    && voteForHttpHeaderMatchesPattern(requestHeaders, configModel.getConfig()) == ABSTAIN
                    && (voteForDefaultFallback(configModel.getConfig()) == VALIDATE_OTP
                    || voteForDefaultFallback(configModel.getConfig()) == ABSTAIN)) {
                return true;
            }
            return false;
        });
    }

    private boolean containsConditionalOtpConfig(Map config) {
        return config.containsKey(OTP_CONTROL_USER_ATTRIBUTE)
                || config.containsKey(SKIP_OTP_ROLE)
                || config.containsKey(FORCE_OTP_ROLE)
                || config.containsKey(SKIP_OTP_FOR_HTTP_HEADER)
                || config.containsKey(FORCE_OTP_FOR_HTTP_HEADER)
                || config.containsKey(DEFAULT_OTP_OUTCOME);
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        if (!isOTPRequired(session, realm, user)) {
            user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        } else if (user.getRequiredActionsStream().noneMatch(UserModel.RequiredAction.CONFIGURE_TOTP.name()::equals)) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP.name());
        }
    }







//
//
    @Override
    public boolean requiresUser() {
        return true;
    }
//
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return getCredentialProvider(session).isConfiguredFor(realm, user);
    }
//
//    @Override
//    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
//
//    }
//
    public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OTPCredentialProvider)session.getProvider(CredentialProvider.class, "keycloak-otp");
    }
//
    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }
//
    @Override
    public void action(AuthenticationFlowContext context) {}
//
    @Override
    public void close() {

    }
}