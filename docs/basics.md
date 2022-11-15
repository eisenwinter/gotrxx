# The basics

gotrxx is designed for a constraint userbase (clients, family members, friends etc) but may also be used as a public
authorization server with open registration.

Its main purpose is to grant authorization via the OAuth protocol. It differs from most well-established OAuth turnkey solutions
because it is designed for said constraint userbases and user consent is always implicitly given.

The main entities involved in the gotrxx system are discussed below.

## Users

A user is someone who can gain access through the authorization server. A user consists mainly of a way to contact the user (email address or phone number) and a password.

## Roles

A user may be in `zero` to `n` roles, how those roles are treated is subject to the implementing solutions.
gotrxx itself comes with two default roles, `admin` which grants the administration rights for the gotrxx instance
and `inviter` which is used to grant a user the right to invite people to register an account.

Any further usage of the roles systems may be decided by the implementing system. 

## Applications

An application defines a system using gotrxx to identify a user. 
To use gotrxx with your application it has to be registered within gotrxx.

Applications are split into `confidential applications`, which can store secret information safely (like Backend Services) and `public applications` which are not able to store secret information securely (like SPAs and Mobile Applications).

An application may be `implicitly granted` which means that any user registered may also use this application as long as their valid credentials are entered. Otherwise, it's `explicitly granted` which means the application may only be used by a pre-approved user.

An application may be eligible for `zero`` up to `n` OAuth flows.

The possible flow types are:

`authorization_code`, `refresh_token`, `client_credentials` and `password`.

When using `authorization_code` the application may also specify `Login Redirect URIs` and `Logout URIs` as well as the
information if `Proof Key of Exchange` is required. For `confidential` applications, there is also a `client_secret` to authorize requests.

For further information regarding OAuth and OAuth-Flows please see: https://datatracker.ietf.org/doc/html/rfc6749

## Authorizations

An authorization grants a user access to an application, this means a user is eligible to sign into
the application with his credentials.

There are two types of authorizations.
`automatically granted authorizations` are authorizations that automatically get granted when the user signs into an application for the first time, 
hence any user registered may use the application automatically.

`manually granted authorizations` that need to be granted by an authority (mostly a user with the `admin` role). Hence
a user needs to receive authorization in advance to use a certain application.

## Invites

An invite is a user invitation that may come with pre-approved application authorizations, scopes and roles for the user that
will automatically be granted once the user signs up.

Depending on the server configuration the invite is mandatory or optional.

## OAuth Flows

Wich OAuth flow to use?

### Public Clients (SPAs, JavaScript Frontends, Apps)

For public clients, the `Authorization Code Flow with PKCE` is recommended. 

### Private Clients (Backend Services, server-side rendered Web Applications)

For private clients, the `Client Credential Flow` is recommended.