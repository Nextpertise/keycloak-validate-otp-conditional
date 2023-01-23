FROM registry.nextpertise.tools/nextpertise-proxy/library/alpine:latest
COPY ./target/conditional-otp-authenticator.jar keycloak-validate-otp-conditional.jar
