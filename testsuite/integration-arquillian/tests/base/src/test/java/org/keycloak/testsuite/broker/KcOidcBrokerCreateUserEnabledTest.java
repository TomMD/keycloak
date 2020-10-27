package org.keycloak.testsuite.broker;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.representations.idm.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.keycloak.models.utils.DefaultAuthenticationFlows.IDP_REVIEW_PROFILE_CONFIG_ALIAS;
import static org.keycloak.testsuite.broker.BrokerRunOnServerUtil.configureAutoLinkFlow;
import static org.keycloak.testsuite.broker.BrokerTestTools.getConsumerRoot;

public class KcOidcBrokerCreateUserEnabledTest extends AbstractBrokerTest {

    private static final org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(KcOidcBrokerCreateUserEnabledTest.class);

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcOidcBrokerConfiguration.INSTANCE;
    }

    //@Override
    protected Iterable<IdentityProviderMapperRepresentation> createIdentityProviderMappers() {
        return Collections.emptyList();
    }

    static private void setIfUnique(AuthenticationExecutionInfoRepresentation execution, AuthenticationManagementResource flows) {
        logger.debugf("[%s] setIfUnique %s %s %s", execution.getProviderId(), execution.getDisplayName(), execution.getFlowId(), execution.getId());

        if (execution.getProviderId() != null && execution.getProviderId().equals(IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID)) {
            logger.debugf("disable creation %s", execution.getAuthenticationConfig());

            AuthenticatorConfigRepresentation config = flows.getAuthenticatorConfig(execution.getAuthenticationConfig());
            Map<String, String> configMap = config.getConfig();
            configMap.put("disable.user.creation", "true");
            flows.updateAuthenticatorConfig(config.getId(), config);
        } else if (execution.getAlias() != null && execution.getAlias().equals(IDP_REVIEW_PROFILE_CONFIG_ALIAS)) {
            logger.debugf("disable update profile");
            AuthenticatorConfigRepresentation config = flows.getAuthenticatorConfig(execution.getAuthenticationConfig());
            config.getConfig().put("update.profile.on.first.login", IdentityProviderRepresentation.UPFLM_OFF);
            flows.updateAuthenticatorConfig(config.getId(), config);
        }
    }

    /**
     * Tests that unknown user can't login from federated identity when automatic creation is disabled.
     */
    @Test
    public void testLoginUnknownUser() {
        getTestingClient().server(bc.consumerRealmName()).run(configureAutoLinkFlow(bc.getIDPAlias()));
        updateExecutions(KcOidcBrokerCreateUserEnabledTest::setIfUnique, BrokerRunOnServerUtil.AUTO_LINK);

        driver.navigate().to(getAccountUrl(getConsumerRoot(), bc.consumerRealmName()));
        logger.debugf("Login : START");
        logInWithBroker(bc);
        logger.debugf("Login : END");

        errorPage.assertCurrent();
        assertEquals("Unexpected error when handling authentication request to identity provider.", errorPage.getError());

        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        org.junit.Assert.assertThat(realm.users().search(bc.getUserLogin()), Matchers.empty());
    }

    /**
     * Tests that known user can login from federated identity when automatic creation is disabled.
     */
    @Test
    public void testLoginExistingUser() {
        createUser(bc.getUserLogin()); // create user in consumer realm

        getTestingClient().server(bc.consumerRealmName()).run(configureAutoLinkFlow(bc.getIDPAlias()));
        updateExecutions(KcOidcBrokerCreateUserEnabledTest::setIfUnique, BrokerRunOnServerUtil.AUTO_LINK);
        updateExecutions(KcOidcBrokerCreateUserEnabledTest::setDisabled, "first broker login");

        { // Just to be sure of pre conditions
            // user exist without federated identities
            List<FederatedIdentityRepresentation> identities = getFederatedIdentityRepresentations();
            org.junit.Assert.assertThat(identities, Matchers.is(Matchers.empty()));
        }
        driver.navigate().to(getAccountUrl(getConsumerRoot(), bc.consumerRealmName()));
        logger.debugf("Login : START");
        logInWithBroker(bc);
        logger.debugf("Login : END");

        logger.debugf("account management : ASSERT");
        assertLoggedInAccountManagement();

        logger.debugf("account management : UPDATE");
        accountUpdateProfilePage.updateProfile("FirstName", "LastName", bc.getUserEmail());

        logger.debugf("user exist with a federated identities : ASSERT");
        { // user exist with a federated identities
            List<FederatedIdentityRepresentation> identities = getFederatedIdentityRepresentations();
            org.junit.Assert.assertThat(identities, Matchers.hasSize(1));
        }
    }

    private List<FederatedIdentityRepresentation> getFederatedIdentityRepresentations() {
        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        List<UserRepresentation> users = realm.users().search(bc.getUserLogin());
        org.junit.Assert.assertThat(users, Matchers.hasSize(1));
        UserRepresentation userRepresentation = users.get(0);
        UserResource userResource = realm.users().get(userRepresentation.getId());
        return userResource.getFederatedIdentity();
    }

    private static void setDisabled(AuthenticationExecutionInfoRepresentation execution, AuthenticationManagementResource flows) {

        if (
                "Confirm link existing account".equals(execution.getDisplayName())
                        || "Verify Existing Account By Email".equals(execution.getDisplayName())
                        || "Verify Existing Account By Re-authentication".equals(execution.getDisplayName())
                        || "Account verification options".equals(execution.getDisplayName())
        ) {
            execution.setRequirement(AuthenticationExecutionModel.Requirement.DISABLED.name());
            logger.debugf("%s DISABLED MANUALLY %s", execution.getDisplayName(), execution.getRequirement());
        }
        logger.debugf("(%s) => %s", execution.getDisplayName(), execution.getRequirement());

    }
}
