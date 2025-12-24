# HTTP Driver for Kipchak

This driver is an HTTP client based on the illuminate/http package that ships with Laravel.

It is used to make HTTP requests within Kipchak.

#### Composer Package 

`kipchak/driver-http`

#### Sample Config File:

This driver does not require any configuration.

## How to use it?

Install it via composer: `composer require kipchak/driver-http`.

### Example Usage

```php
// Load the HTTP driver.
$http = \Mamluk\Kipchak\Driver\Http\Driver::get()
// Use the HTTP client ($http) client as you normally would.
```
See the methods available in the client here: https://laravel.com/docs/12.x/http-client. All methods
in the Laravel documentation called via `Http::method()` are available via `$http->method() in Kipchak.

## What is a Kipchak Driver?

Kipchak Drivers are used to connect Kipchak to various data sources or storage systems. 

They provide a standardized interface for interacting with different data sources, allowing developers to 
focus on building their applications rather than dealing with the complexities of each data source.

Drivers were introduced as a part of the Kipchak 2.0 release.

Drivers are basically Container Dependencies injected into Kipchak's Service Container.

## How do Kipchak Drivers work?

Kipchak drivers are wired into the Service Container via a config file (where required).

Each driver defines an implementation of Kipchak's Driver Interface. 
Where applicable, the dependency may accept a parameter for a specific instance of the driver specified as a onfig property, 
for instance, in the case of multiple database connections or S3 buckets.

So you may access the driver by invoking \Mamluk\Kipchak\Driver\Http\Driver::get('default'), where 
`default` is the name of the connection specified in the config file.

**NOTE: This driver does not require any configuration.**