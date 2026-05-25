# Changelog

## [0.1.0] - 2026-05-25

### Added
- `Provider.php` - Custom Azure OpenID Connect Socialite provider
- `JwtValidator.php` - Validates Azure JWT `id_token`
- `AzureTokenExtendSocialite.php` - Registers `azure-token` Socialite driver
- `AzureTokenServiceProvider.php` - Boots package and attaches Socialite listener
- JWT signature verification using Azure JWKS
- Token-only authentication flow (no Microsoft Graph)