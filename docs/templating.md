# How to customize templates

Gotrxx uses Go HTML templates[^1]. All templates and their assets are located in the `templates` folder.

```
templates
├───pages
│   │   404.gohtml
│   │   change_email.gohtml
│   │   change_mfa.gohtml
│   │   change_password.gohtml
│   │   confirm.gohtml
│   │   error.gohtml
│   │   invite.gohtml
│   │   layout.gohtml
│   │   provision_mfa.gohtml
│   │   recover_password.gohtml
│   │   request_password_recovery.gohtml
│   │   signin.gohtml
│   │   signup.gohtml
│   │   user.gohtml
│   │
│   └───components
│           alert-error.gohtml
│           alert-success.gohtml
│           language-selector.gohtml
│
├───email
│       template.html
│ ...
```

## Customizing Templates

To customize the templates for your needs:

1. Copy the entire `templates` folder to your project
2. Modify the `.gohtml` files to match your design requirements
3. Make sure to preserve all `{{ .csrfField }}` fields as they are essential for CSRF protection
4. You can modify existing components or add new ones in the `components` folder
5. The `layout.gohtml` file serves as the base template for all pages

The template system now uses `.gohtml` extension and supports layouts and components for better organization and reusability.

## Using the templates 

The templates can be integrated into the binary by building gotrxx from the source, just the binary needs to be deployed without any additional files. 

If no custom build is wanted the template files can be used with an existing binary, to archive this put the `templates` folder next to your gotrxx binary.

```
gotrxx
+ templates
│   ...
```

and configure your gotrxx with 

```
server:
  load-template-folder: true
```

or if you are using the environment variable-based configuration

```
TRXX_SERVER_LOAD_TEMPLATE_FOLDER=true
```


[^1]: https://pkg.go.dev/html/template
