<?php

namespace Mcgill\OpenIdAzureToken;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use RuntimeException;
use UnexpectedValueException;

class JwtValidator
{
    // HTTP client used to call Azure endpoints.
    private Client $http;

    public function __construct(?Client $http = null)
    {
        // If no client is passed in, create one with a 10 second timeout.
        $this->http = $http ?? new Client([
            'timeout' => 10,
        ]);
    }

    public function validate(string $jwt, string $tenant, string $clientId ): array 
    {
        // Step 1: get Azure OpenID configuration.
        $config = $this->fetchOpenIdConfiguration($tenant);

        // Read issuer and jwks_uri from that config.
        $issuer = $config['issuer'] ?? null;
        $jwksUri = $config['jwks_uri'] ?? null;

        // If Azure config does not contain these, stop.
        if (!$issuer || !$jwksUri) {
            throw new RuntimeException('OpenID configuration is missing issuer or jwks_uri');
        }

        // Step 2: download Azure public keys.
        $jwks = $this->fetchJwks($jwksUri);

        try {
            // Allow 60 seconds of clock difference.
            JWT::$leeway = 60;

            // Step 3: verify signature and decode token using Azure public keys.
            $decoded = JWT::decode($jwt, JWK::parseKeySet($jwks));
        } catch (ExpiredException $e) {
            throw new RuntimeException('ID token has expired', 0, $e); // Token is expired.
        } catch (UnexpectedValueException $e) {
            throw new RuntimeException('Invalid ID token signature or format', 0, $e); // Signature invalid or token format wrong.
        }

        $claims = json_decode(json_encode($decoded), true); // Convert decoded object into a PHP array.

        // If conversion failed, stop.
        if (!is_array($claims)) {
            throw new RuntimeException('Could not read token claims');
        }

        // Step 4: check issuer.
        $this->assertClaim($claims, 'iss', $issuer, 'Invalid issuer');

        // Step 5: check audience.
        $aud = $claims['aud'] ?? null;
        if (is_array($aud)) {
            // Some tokens may have multiple audiences.
            if (!in_array($clientId, $aud, true)) {
                throw new RuntimeException('Invalid audience');
            }
        } elseif ($aud !== $clientId) {
            // If audience is a single string, compare directly.
            throw new RuntimeException('Invalid audience');
        }

        // Step 6: check expiry again as a safe backup.
        if (isset($claims['exp']) && (int) $claims['exp'] < time()) {
            throw new RuntimeException('Token expired');
        }

        // Step 7: return the verified claims.
        return $claims;
    }

    private function fetchOpenIdConfiguration(string $tenant): array
    {
        // Build Azure OpenID config URL for the tenant.
        $url = sprintf(
            'https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration',
            trim($tenant)
        );

        $response = $this->http->get($url); // Call Azure.

        $data = json_decode((string) $response->getBody(), true); // Convert JSON response to array.

        // If response is not valid JSON, stop.
        if (!is_array($data)) {
            throw new RuntimeException('Invalid OpenID configuration response');
        }

        return $data; // Return config data.
    }

    private function fetchJwks(string $jwksUri): array
    {
        $response = $this->http->get($jwksUri); // Call the JWKS endpoint.

        $data = json_decode((string) $response->getBody(), true); // Convert JSON response to array.

        // JWKS must contain a "keys" array.
        if (!is_array($data) || !isset($data['keys']) || !is_array($data['keys'])) {
            throw new RuntimeException('Invalid JWKS response');
        }

        return $data; // Return public keys.
    }

    private function assertClaim(array $claims, string $key, string $expected, string $errorMessage): void
    {
        // Check whether claim exists and matches expected value.
        if (!isset($claims[$key]) || $claims[$key] !== $expected) {
            throw new RuntimeException($errorMessage);
        }
    }
}