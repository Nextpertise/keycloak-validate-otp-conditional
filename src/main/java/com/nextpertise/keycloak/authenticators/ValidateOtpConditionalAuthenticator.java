package com.nextpertise.keycloak.authenticators;

import org.jboss.logging.Logger;
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
import org.keycloak.models.UserModel;

import java.util.Optional;

import static com.nextpertise.keycloak.authenticators.ValidateOtpConditionalAuthenticator.OtpDecision.ABSTAIN;
import static com.nextpertise.keycloak.authenticators.ValidateOtpConditionalAuthenticator.OtpDecision.VALIDATE_OTP;
import static com.nextpertise.keycloak.authenticators.ValidateOtpConditionalAuthenticator.OtpDecision.SKIP_OTP;

/**
 * @author <a href="mailto:teun@nextpertise.nl">Teun Ouwehand</a>
 * @version $Revision: 1 $
 */
public class ValidateOtpConditionalAuthenticator implements Authenticator, CredentialValidator<OTPCredentialProvider> {

    private static final Logger logger = Logger.getLogger(ValidateOtpConditionalAuthenticator.class);

    public static final String SKIP = "skip";

    public static final String FORCE = "force";

    public static final String OTP_CONTROL_USER_ATTRIBUTE = "otpControlAttribute";

    public static final String DEFAULT_OTP_OUTCOME = "defaultOtpOutcome";

    enum OtpDecision {
        SKIP_OTP, VALIDATE_OTP, ABSTAIN
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.infof("Validate Otp Conditional Authenticator");
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();

        if (tryConcludeBasedOn(voteForUserOtpControlAttribute(context.getUser(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForDefaultFallback(config), context)) {
            return;
        }
        context.success();
    }

    private void validateOtp(AuthenticationFlowContext context) {
        logger.infof("Called validateOtp");
        if (!getCredentialProvider(context.getSession()).isConfiguredFor(context.getRealm(), context.getUser())) {
            logger.infof("ValidateOtp: IP not whitelisted and TOTP is not configured.");
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            // TODO: Check if IP Whitelisting module is called/failed, for now we assume this is the case.
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "IP not whitelisted and TOTP is not configured.");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
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
            logger.infof("ValidateOtp: TOTP credential missing.");
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "TOTP credential missing");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        boolean valid = getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), new UserCredentialModel(credentialId, OTPCredentialModel.TYPE, otp));
        if (!valid) {
            logger.infof("ValidateOtp: TOTP credential invalid.");
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "TOTP credential invalid");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        logger.infof("ValidateOtp: TOTP pass.");
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
                logger.infof("SKIP_OTP=True, skipping ..");
                context.success();
                return true;

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

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // We will check in authenticate method if the user needs to authenticate with TOTP.
        return true;
    }

    @Override
    public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OTPCredentialProvider)session.getProvider(CredentialProvider.class, "keycloak-otp");
    }

    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @Override
    public void action(AuthenticationFlowContext context) {}

    @Override
    public void close() {}
}