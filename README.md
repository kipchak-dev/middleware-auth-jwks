# JWKS Middleware for Kipchak

This Middleware package provides OAuth 2.0 JWT Bearer Token Authentication support for Kipchak APIs using JWKS.

#### Composer Package

`kipchak/middleware-auth-jwks`

## How to use it?

Install it via composer: `composer require kipchak/middleware-auth-jwks`.

Then just ensure you have appropriate settings configured in `kipchak.auth.jwks.php` config file in the root of your project.

For a sample, please see: https://1x.ax/mamluk/kipchak/starter/~files/master/config/kipchak.auth.jwks.php.

## What is a Kipchak Middleware?

Kipchak Middleware is a standard PHP PSR-15 middleware.

Middleware is a component that sits between the request and response of a web application, allowing for interception
and modification of the request and response data. In the context of Kipchak, middleware can be used to handle errors,
authentication, and other cross-cutting concerns that are common across one or more API endpoints.
