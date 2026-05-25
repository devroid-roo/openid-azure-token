<?php

namespace Mcgill\OpenIdAzureToken;
use SocialiteProviders\Manager\SocialiteWasCalled;

// This class registers our custom Socialite driver
class AzureTokenExtendSocialite
{
    // Called when Socialite is being initialized
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        // Register our custom driver name "azure-token"
        $socialiteWasCalled->extendSocialite(
            'azure-token',
            Provider::class
        );
    }
}