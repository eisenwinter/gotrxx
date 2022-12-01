# Guide: oidc client

This guide walks you through using [oidc-client-ts](https://github.com/authts/oidc-client-ts) and gotrxx together.
It guides you through setting up authorization code flow with your SPA application.


## Creating the application in gotrxx

Either use gotrxx-admin to create a new application, your application should have `Confidentiality` set to public, use PKCE (check the box), and the following flows checked `authorization_code`, `refresh_token` and the `offline_access` scope.

Set the redirect URI accordingly.

If you are using the command line interface run:

```sh
gotrxx app create -c public -f authorization_code -f refresh_token -o offline_access -n MY_APPLICATION_NAME -r https://login.example.com/MY_REDIRECT_URL -t implicit_granted -p  MY_CLIENT_ID
```

(Replace MY_APPLICATION_NAME with your application name, MY_CLIENT_ID with your client id and MY_REDIRECT_URL with your redirect URI)


## Setting up oidc-client-ts

Okay, I was halfway through writing this when I figured they have a very simple example page to show you how to work 
with it. I will refer you to [https://github.com/authts/oidc-client-ts/tree/main/samples/Parcel/src/oidc-client](https://github.com/authts/oidc-client-ts/tree/main/samples/Parcel/src/oidc-client). 

Adapt the [settings](https://github.com/authts/oidc-client-ts/blob/main/samples/Parcel/src/oidc-client/sample-settings.js) for the 
example to match your application:

```js
{
    authority: "login.example.com",
    client_id: "MY_CLIENT_ID", //replace with your client from above
    redirect_uri: "https://login.example.com/MY_REDIRECT_URI" , // replace with your redirect uri
    response_type: "code",
    scope: "offline_access", 
    filterProtocolClaims: true,
    loadUserInfo: false
}
```

This should be enough to have a working example of gotrxx working with a JavaScript Site and authorization code flow.

For a deeper dive either dig deeper into the oidc-client-ts docs or if you are using a certain framework look at one of the already
existing framework integrations to make your life easier. Sorry, this went kind of short, but I wouldn't want to build the same example again.