<?php

namespace Mcgill\OpenIdAzureToken;
use Illuminate\Support\ServiceProvider;
use SocialiteProviders\Manager\SocialiteWasCalled;

class AzureTokenServiceProvider extends ServiceProvider
{
    // Bootstrap package services.
    public function boot(): void
    {
        $this->app['events']->listen(

            SocialiteWasCalled::class,       // Event fired when Socialite loads providers
            AzureTokenExtendSocialite::class // custom Azure driver.
        );
    }
}