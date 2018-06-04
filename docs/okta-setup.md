# Okta

This page summarises the steps needed to setup an Okta application that uses the OIDC flow to expose user groups as JWT claims. This will describe the process using an Okta developer account, but an upgraded account would work similarly.

## Create an application

- Sign in to your Okta account and change to the Classic UI view by selecting the option in the top left drop down.
- Go to the Applications tab and create a new Web application with the OIDC sign on method. Specify a login redirect URI of `http://127.0.0.1:8888/callback`. 
- In the General tab, make sure that authorisation code and refresh token are set as allowed grant types.
- In the Sign On tab, edit the OpenID Connect ID Token section, changing the groups claim type to filter and the groups claim filter to groups with a regex value of `.*`.
- In the Assignments tab, assign people and groups to your application as necessary.

## Expose the groups claim

- Go to Security, API and add an new authorisation server (or edit the default server). The Audience field corresponds to the [audience](https://tools.ietf.org/html/rfc7519#section-4.1.3) claim.
- In the Scopes tab, add a new scope called groups and include it in public metadata.
- In the Claims tab, add a new claim called groups that is included with the ID token, of value type Groups, with a Regex filter of `.*` and that is included in the groups scope.
- In the Access Policies tab add a new access policy and assign your application. 
- Add a new rule to your access policcy called Default Policy Rule keeping all the settings as they are.
- You can test your setup by going to the Token Preview tab, specifying your application as the client, grant type as authorisation code and scopes as groups and openid. The returned payload should contain the list of groups containing the user you chose.
- Note that okta-kubectl-auth uses scopes of groups, openid, profile, email and (if supported) offline_access to return `email` and `preferred_username` claims as well as a refresh token.