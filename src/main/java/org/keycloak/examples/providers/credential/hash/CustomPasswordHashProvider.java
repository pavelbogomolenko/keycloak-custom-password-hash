package org.keycloak.examples.providers.credential.hash;

import org.keycloak.Config;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserCredentialModel;

import org.apache.commons.codec.digest.DigestUtils;

public class CustomPasswordHashProvider implements PasswordHashProviderFactory, PasswordHashProvider {

    public static final String ID = "custom";

    public CredentialModel encode(String rawPassword, int iterations) {
        byte[] salt = getSalt();
        String encodedPassword = encode(rawPassword, iterations, salt);

        CredentialModel credentials = new CredentialModel();
        credentials.setAlgorithm(ID);
        credentials.setType(UserCredentialModel.PASSWORD);
        credentials.setSalt(salt);
        credentials.setHashIterations(iterations);
        credentials.setValue(encodedPassword);
        return credentials;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, CredentialModel credential) {
        return credential.getHashIterations() == policy.getHashIterations() && ID.equals(credential.getAlgorithm());
    }

    @Override
    public void encode(String rawPassword, PasswordPolicy policy, CredentialModel credential) {
        byte[] salt = getSalt();
        String encodedPassword = encode(rawPassword, policy.getHashIterations(), salt);

        credential.setAlgorithm(ID);
        credential.setType(UserCredentialModel.PASSWORD);
        credential.setSalt(salt);
        credential.setHashIterations(policy.getHashIterations());
        credential.setValue(encodedPassword);
    }

    @Override
    public boolean verify(String rawPassword, CredentialModel credential) {
        String encodedPassword = encode(rawPassword, credential.getHashIterations(), credential.getSalt());

        return encodedPassword.equals(credential.getValue());
    }

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    private String encode(String rawPassword, int iterations, byte[] salt) {
        try {
            String hexPrivateCreditional = DigestUtils.sha1Hex(rawPassword.getBytes("UTF-8"));
            String stringSalt = new String(salt);

            return BCrypt.hashpw(hexPrivateCreditional, stringSalt);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private byte[] getSalt() {
        return BCrypt
                .gensalt(5)
                .getBytes();
    }
}
