package de.novatec.bpm.webapp.impl.security.auth;

import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.webapp.impl.security.auth.Authentications;

/**
 * This Servlet filter relies on the Servlet container (application server) to
 * authenticate a user and only forward a request to the application upon
 * successful authentication.
 *
 * In addition this variation expects the container to also look up the groups.
 *
 * The filter passes the username and groups provided by the container through
 * the Servlet API into the Servlet session used by the Camunda REST API.
 *
 * @author Falko Menge
 */
public class ContainerBasedUserAndGroupsAuthenticationFilter extends ContainerBasedUserAuthenticationFilter {

  @Override
  protected void doLogin(Authentications authentications, String username, String engineName, HttpServletRequest request) {
    new ContainerBasedUserAuthenticationResource() {

      public ContainerBasedUserAuthenticationResource setRequest(HttpServletRequest request) {
        this.request = request;
        return this;
      }

      protected List<String> getGroupsOfUser(org.camunda.bpm.engine.ProcessEngine engine, String userId) {
        List<String> groupIds = new LinkedList<String>();

        // ouch - but servlet API has no getGroups(), for that one has to cast
        // to (internal) implementation of Principal
        for (Group group : engine.getIdentityService().createGroupQuery().list()) {
          if (request.isUserInRole(group.getId())) {
            groupIds.add(group.getId());
          }
        }

        return groupIds;
      };
    }.setRequest(request).doLogin(engineName, username, authentications);
  }

}
