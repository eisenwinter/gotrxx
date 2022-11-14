# The basics

gotrxx is designed for contraint userbase (clients, family members, friends etc) but may also be used as a public
authorization server with open registration.

Its main purpose is grant authorization via the oauth protocol, it differs from most well etablished oauth turnkey solutions
that it is able to constraint user access on a per app basis and user consent is always consider as implicit given.

The main entities involved in the gotrxx system are discussed below.

## Users

A user is someone who can gain access through the authorization server. A user consist mainly of a email address and a password.

## Roles

A user may be in `zero` to `n` roles, how those roles are treated is subject to the implementing solutions. 
gotrxx itself comes with two default roles, `admin` which basically grants the administration rights for the gotrxx
and `inviter` which is used to grant a user the right to invite people to register an account.

Any further usage of the roles systems may be decided by the implementing system. 

## Applications

An application defines a application using gotrxx to identify a user. 
In order to use gotrxx with your application it has to be registred within gotrxx.

Applications are split into `confidental applications`, wich are able to store secret information safely (like Backend Services) and 
`public application` wich are not able to store secret information securly (like SPAs and Mobile Applications).

An application may be either `implicit granted` wich means that any user registred may also use this application as long as 
there valid credentials are entered (authorizations for this application are automatically granted, see Authorizations), or 
`explicit granted` wich means the application may only be used by a pre-approved user.

An application may be eligble for `zero` up to `n` oauth flows.

The possible flow types are:

`authorization_code`, `refresh_token`, `client_credentials` and `password`.

When using `authorization_code` the application may also specify `Login Redirect URIs` and `Logout URIs` as well as the
information if `Proof Key of Exchange` is required.

For `confidential` applicications there is also a `client_secret` to authorize requests.

For further information regarding OAuth and OAuth-Flows please see: https://datatracker.ietf.org/doc/html/rfc6749


## Authorizations

An authorization is grants a user authorization for an application, this means a user is eligble to sign into
the application with his credentials.

There are two types of authorizations, `automatically granted authorizations` are authorizations that automatically get 
granted when user signs into a application for the first time, hence any user registred may use the application automatically 
and `manually granted authorizations` which need need to be granted by a authority (mostly the a user with the `admin` role). Hence
a user needs to receive authorization in advance to use a certain application.

## Invites

An invite is a user invitation that may come with pre-approved application authorizations, scopes and roles for the user that
will automatically be granted once the user signs up.

Depending on the server configuration the invite is mandatory or optional.

## OAuth Flows

Wich oauth flow to use?

### Public Clients (SPAs, JavaScript Frontends, Apps)

For public clients the `Authorization Code Flow with PKCE` is recommended. 

### Private Clients (Backend Services, server-side rendered Web Applications)

For private clients the `Client Credential Flow` is recommended.