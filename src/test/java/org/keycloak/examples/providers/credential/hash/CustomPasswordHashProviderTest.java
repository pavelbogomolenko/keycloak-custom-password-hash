package org.keycloak.examples.providers.credential.hash;

import org.junit.Assert;
import org.junit.Test;

import org.keycloak.credential.CredentialModel;

public class CustomPasswordHashProviderTest  {
    @Test
    public void verify() throws Exception {
        String plainPrivateCredential = "admin";

        CustomPasswordHashProvider hashProvider = new CustomPasswordHashProvider();

        CredentialModel credentialModel = hashProvider.encode(plainPrivateCredential, 1);

        Assert.assertTrue(hashProvider.verify(plainPrivateCredential, credentialModel));
    }
}
