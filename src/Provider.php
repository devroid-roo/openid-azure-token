<?php

namespace Mcgill\OpenIdAzureToken;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Mcgill\OpenIdAzureToken\JwtValidator;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'AZURE_TOKEN_ONLY'; // A unique name for this provider.

    protected $scopes = ['openid', 'profile', 'email']; // Azure OIDC scopes.

    protected $scopeSeparator = ' '; // scopes separated by space.

    // Extra config keys.
    public static function additionalConfigKeys(): array
    {
        return ['tenant', 'proxy'];
    }

    // Get the Azure tenant value from config.
    protected function getTenant(): string
    {
        return trim($this->getConfig('tenant', 'common'));
    }

    // Build the base Azure v2 endpoint for the selected tenant.
    protected function getBaseUrl(): string
    {
        return 'https://login.microsoftonline.com/' . $this->getTenant() . '/oauth2/v2.0';
    }

    // Redirect user to Azure login page.
    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->getBaseUrl() . '/authorize', $state);
    }

    // Azure token endpoint.
    protected function getTokenUrl(): string
    {
        return $this->getBaseUrl() . '/token';
    }

    // Main login flow.
    public function user()
    {
        // Return cached user if already built.
        if ($this->user) {
            return $this->user;
        }

        // Check OAuth state to protect against CSRF.
        if ($this->hasInvalidState()) {
            throw new \InvalidArgumentException('Invalid state');
        }

        $tokenResponse = $this->getAccessTokenResponse($this->request->input('code')); // Exchange auth code for tokens.

        if (empty($tokenResponse['id_token'])) {
            throw new \RuntimeException('No id_token returned from Azure');
        }

        // validate token and return claims.
        $claims = (new JwtValidator())->validate(
            $tokenResponse['id_token'],
            $this->getTenant(),
            $this->getConfig('client_id'),
        );

        $this->user = $this->mapUserToObject($claims); // Map token claims into a Socialite user object.

        // Attach token data to the user object.
        return $this->user
            ->setToken($tokenResponse['access_token'] ?? null)
            ->setRefreshToken($tokenResponse['refresh_token'] ?? null)
            ->setExpiresIn($tokenResponse['expires_in'] ?? null);
    }

    // Convert Azure claims into a Socialite user object.
    protected function mapUserToObject(array $user)
    {
        $email = $user['email'] ?? ($user['preferred_username'] ?? null);

        return (new User())->setRaw($user)->map([
            'id'    => $user['sub'] ?? null,
            'name'  => $user['name'] ?? null,
            'email' => $email,
        ]);
    }

    // Required by AbstractProvider.
    protected function getUserByToken($token)
    {
        return [];
    }

}