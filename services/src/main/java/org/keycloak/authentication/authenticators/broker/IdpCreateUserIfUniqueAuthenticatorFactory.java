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

package org.keycloak.authentication.authenticators.broker;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class IdpCreateUserIfUniqueAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "idp-create-user-if-unique";
    static IdpCreateUserIfUniqueAuthenticator SINGLETON = new IdpCreateUserIfUniqueAuthenticator();

    public static final String REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION = "require.password.update.after.registration";
    public static final String DISABLE_USER_CREATION = "disable.user.creation";

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return "createUserIfUnique";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Create User If Unique";
    }

    @Override
    public String getHelpText() {
        return "Detect if there is existing Keycloak account with same email like identity provider. If no, create new user";
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty requirePasswordProperty = new ProviderConfigProperty();
        requirePasswordProperty.setName(REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION);
        requirePasswordProperty.setLabel("Require Password Update After Registration");
        requirePasswordProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        requirePasswordProperty.setHelpText("If this option is true and new user is successfully imported from Identity Provider to Keycloak (there is no duplicated email or username detected in Keycloak DB), then this user is required to update his password");
        configProperties.add(requirePasswordProperty);

        ProviderConfigProperty disableUserCreationProperty = new ProviderConfigProperty();
        disableUserCreationProperty.setName(DISABLE_USER_CREATION);
        disableUserCreationProperty.setLabel("Disable user creation");
        disableUserCreationProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        disableUserCreationProperty.setHelpText("(False by default) If this option is true and there is no user matching id provided by the Identity Provider in Keycloak, a user will not be created.");
        disableUserCreationProperty.setDefaultValue(false);

        configProperties.add(disableUserCreationProperty);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
