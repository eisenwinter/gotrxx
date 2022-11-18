# Running gotrxx admin

gotrxx-admin is a web ui designed to do all basic administrative tasks that come around.
It supports `application`, `user` and `invitation` management at the convenience of a click.

## Github pages hosted version

There is a Github Pages hosted version available at https://eisenwinter.github.io/gotrxx-admin/.
For more information check https://github.com/eisenwinter/gotrxx-admin.

## Requirements

This setup assumes you already have gotrxx instance running and a registered user account for your administrative tasks.
Be sure you have the management endpoint enabled in the configuration file (`manage-endpoint.enable: true`).

**Application setup**

```
gotrxx app create -c public -f authorization_code -f refresh_token -o offline_access -n adminui -r http://localhost:3000/#/oidc-callback -t implicit_granted -p  gotrxxadmin
```

?> Replace `http://localhost:8080/#/oidc-callback` with your URL, unless you only want to run it locally then this is fine.

The user needs to be in the `admin` role. A user account can be added to the `admin` role by issuing the following command:

```
gotrxx user role add user@gotrxx.local admin
```

?> Replace `user@gotrxx.local` with your email address.