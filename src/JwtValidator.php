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
    private Client $http;

    public function __construct(?Client $http = null)
    {
        $this->http = $http ?? new Client([
            'timeout' => 10,
        ]);
    }

    public function validate(string $jwt, string $tenant, string $clientId): array
    {
        // Step 1: Get Azure OpenID Connect configuration.
        $config = $this->fetchOpenIdConfiguration($tenant);

        $issuer = $config['issuer'] ?? null;
        $jwksUri = $config['jwks_uri'] ?? null;

        if (!$issuer || !$jwksUri) {
            throw new RuntimeException(
                'OpenID configuration is missing issuer or jwks_uri'
            );
        }

        // Step 2: Read the JWT header so we know which key (kid)
        // and algorithm (alg) were used to sign this token.
        $header = $this->decodeJwtHeader($jwt);

        $kid = $header['kid'] ?? null;
        $alg = $header['alg'] ?? null;

        if (!$kid) {
            throw new RuntimeException('ID token is missing kid header');
        }

        if (!$alg) {
            throw new RuntimeException('ID token is missing alg header');
        }

        // Microsoft Entra ID tokens are expected to use RS256
        // for this application.
        if ($alg !== 'RS256') {
            throw new RuntimeException(
                'Unsupported ID token signing algorithm: ' . $alg
            );
        }

        // Step 3: Download Azure public signing keys.
        $jwks = $this->fetchJwks($jwksUri);

        // Step 4: Find the exact Azure key referenced by the JWT.
        $matchingKey = null;

        foreach ($jwks['keys'] as $key) {
            if (($key['kid'] ?? null) === $kid) {
                $matchingKey = $key;
                break;
            }
        }

        if (!$matchingKey) {
            throw new RuntimeException(
                'No Azure signing key found for kid: ' . $kid
            );
        }

        // The Azure JWK response may omit "alg".
        // Firebase JWT expects it, so supply the algorithm that
        // we have already validated from the token header.
        $matchingKey['alg'] = $alg;

        // The application expects RSA signing keys.
        if (($matchingKey['kty'] ?? null) !== 'RSA') {
            throw new RuntimeException('Azure signing key is not RSA');
        }

        // The key must be intended for signatures.
        if (
            isset($matchingKey['use']) &&
            $matchingKey['use'] !== 'sig'
        ) {
            throw new RuntimeException(
                'Azure signing key is not intended for signatures'
            );
        }

        // Pass only the matched key to Firebase.
        $keySet = [
            'keys' => [
                $matchingKey,
            ],
        ];

        try {
            // Allow 60 seconds of clock difference.
            JWT::$leeway = 60;

            // Step 5: Verify the JWT signature and decode the claims.
            $decoded = JWT::decode(
                $jwt,
                JWK::parseKeySet($keySet)
            );

        } catch (ExpiredException $e) {
            throw new RuntimeException(
                'ID token has expired',
                0,
                $e
            );

        } catch (UnexpectedValueException $e) {
            throw new RuntimeException(
                'Invalid ID token: ' . $e->getMessage(),
                0,
                $e
            );
        }

        $claims = json_decode(
            json_encode($decoded),
            true
        );

        if (!is_array($claims)) {
            throw new RuntimeException(
                'Could not read token claims'
            );
        }

        // Step 6: Validate issuer.
        $this->assertClaim(
            $claims,
            'iss',
            $issuer,
            'Invalid issuer'
        );

        // Step 7: Validate audience.
        $aud = $claims['aud'] ?? null;

        if (is_array($aud)) {
            if (!in_array($clientId, $aud, true)) {
                throw new RuntimeException('Invalid audience');
            }
        } elseif ($aud !== $clientId) {
            throw new RuntimeException('Invalid audience');
        }

        // Step 8: Validate expiration.
        if (
            !isset($claims['exp']) ||
            (int) $claims['exp'] < time()
        ) {
            throw new RuntimeException('Token expired');
        }

        return $claims;
    }

    private function fetchOpenIdConfiguration(string $tenant): array
    {
        $url = sprintf(
            'https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration',
            trim($tenant)
        );

        $response = $this->http->get($url);

        $data = json_decode(
            (string) $response->getBody(),
            true
        );

        if (!is_array($data)) {
            throw new RuntimeException(
                'Invalid OpenID configuration response'
            );
        }

        return $data;
    }

    private function fetchJwks(string $jwksUri): array
    {
        $response = $this->http->get($jwksUri);

        $data = json_decode(
            (string) $response->getBody(),
            true
        );

        if (
            !is_array($data) ||
            !isset($data['keys']) ||
            !is_array($data['keys'])
        ) {
            throw new RuntimeException(
                'Invalid JWKS response'
            );
        }

        return $data;
    }

    private function decodeJwtHeader(string $jwt): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new RuntimeException(
                'Invalid JWT format'
            );
        }

        $header = json_decode(
            $this->base64UrlDecode($parts[0]),
            true
        );

        if (!is_array($header)) {
            throw new RuntimeException(
                'Invalid JWT header'
            );
        }

        return $header;
    }

    private function base64UrlDecode(string $value): string
    {
        $remainder = strlen($value) % 4;

        if ($remainder !== 0) {
            $value .= str_repeat(
                '=',
                4 - $remainder
            );
        }

        $decoded = base64_decode(
            strtr(
                $value,
                '-_',
                '+/'
            ),
            true
        );

        if ($decoded === false) {
            throw new RuntimeException(
                'Invalid base64url encoding'
            );
        }

        return $decoded;
    }

    private function assertClaim(
        array $claims,
        string $key,
        string $expected,
        string $errorMessage
    ): void {
        if (
            !isset($claims[$key]) ||
            $claims[$key] !== $expected
        ) {
            throw new RuntimeException($errorMessage);
        }
    }
}