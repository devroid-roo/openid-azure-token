# openid-azure-token

A lightweight Laravel package for Azure Entra ID (OpenID Connect) authentication using token-only sign-in.

This package is built on top of Laravel Socialite and SocialiteProviders. It validates the Azure id_token, reads user identity from JWT claims.

Why this package?

* Laravel-friendly authentication flow
* Minimal OIDC scopes: openid, profile, email
* No Microsoft Graph dependency
* Uses Azure JWKS to validate token signatures
* Keeps sign-in simple for Laravel applications

Features

* Custom Azure OIDC Socialite provider
* JWT validation for Azure id_token
* JWKS-based public key resolution
* Extracts user info from token claims
* Easy integration with Laravel auth flows

Requirements

* PHP 8.1+
* Socialite
* SocialiteProviders Manager

Compatibility

This package will be maintained in two Laravel support tracks:

* Laravel 10 and below
* Laravel 11 and above

The goal is to keep the package API the same while adjusting service provider registration and framework-specific wiring when needed.

Installation

    Install the package through Composer:

    - composer require vendor/openid-azure-token

Configuration

    Add your Azure OIDC settings to .env:

    AZURE_CLIENT_ID=your-client-id
    AZURE_CLIENT_SECRET=your-client-secret
    AZURE_TENANT_ID=your-tenant-id
    AZURE_REDIRECT_URI=https://your-app.com/auth/azure/callback

Register the provider

    Add the package service provider to Laravel if auto-discovery is not used:

    'providers' => [
        // ...
        App\Providers\YourPackageServiceProvider::class,
    ],

Usage

    Redirect the user to Azure login:

    - return Socialite::driver('azure')->redirect();

    Handle the callback:

    - $user = Socialite::driver('azure')->user();

    The package will validate the token and return the user identity from Azure claims.

How it works

1. User clicks sign in with Azure
2. Azure redirects back with an authorization response
3. Package retrieves the id_token
4. JWT is validated using Azure JWKS
5. Claims such as sub, name, and email are extracted
6. Laravel can log the user in or create a local account

Package structure

    openid-azure-token/
    ├── src/
    │   ├── Provider.php
    │   ├── AzureTokenExtendSocialite.php
    │   ├── AzureTokenServiceProvider.php
    │   └── JwtValidator.php
    ├── composer.json
    └── README.md

Planned support approach

We will keep the core token validation logic shared, and only separate framework bootstrapping where Laravel versions differ.

Possible layout:

* src/ for shared package logic
* version-specific service provider setup where needed
* one README with clear compatibility notes

Planned classes

Provider.php

    * Custom Socialite provider that handles Azure OIDC token-based login.

AzureTokenExtendSocialite.php

    * Registers the custom provider with SocialiteProviders.

AzureTokenServiceProvider.php

    * Laravel service provider for package bootstrapping.

JwtValidator.php

    * Validates Azure id_token using JWKS and token claims.
