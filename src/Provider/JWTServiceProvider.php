<?php

/*
 * This file is part of jwt.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Provider;

use Namshi\JOSE\JWS;
use Ethanzway\JWT\JWT;
use Ethanzway\JWT\Factory;
use Ethanzway\JWT\Manager;
use Ethanzway\JWT\Blacklist;
use Lcobucci\JWT\Parser as JWTParser;
use Ethanzway\JWT\Parser\Parser;
use Ethanzway\JWT\Parser\Cookies;
use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Builder as JWTBuilder;
use Ethanzway\JWT\Driver\Namshi;
use Ethanzway\JWT\Driver\Lcobucci;
use Ethanzway\JWT\Parser\AuthHeaders;
use Ethanzway\JWT\Parser\InputSource;
use Ethanzway\JWT\Parser\QueryString;
use Ethanzway\JWT\Parser\RouteParams;
use Ethanzway\JWT\Contracts\Driver;
use Ethanzway\JWT\Contracts\Storage;
use Ethanzway\JWT\Validators\PayloadValidator;
use Ethanzway\JWT\Claims\Factory as ClaimFactory;
use Ethanzway\JWT\Console\JWTGenerateSecretCommand;

class JWTServiceProvider extends ServiceProvider
{
    /**
     * Boot the service provider.
     *
     * @return void
     */
    public function boot()
	{
        $path = realpath(__DIR__.'/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');
	}

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerDriver();
        $this->registerStorage();
        $this->registerBlacklist();

        $this->registerManager();
        $this->registerParser();

        $this->registerJWT();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();
        $this->registerCommand();

        $this->commands('jwt.secret');
    }

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->alias('jwt', JWT::class);
        $this->app->alias('jwt.driver', Driver::class);
        $this->app->alias('jwt.driver.namshi', Namshi::class);
        $this->app->alias('jwt.driver.lcobucci', Lcobucci::class);
        $this->app->alias('jwt.storage', Storage::class);
        $this->app->alias('jwt.manager', Manager::class);
        $this->app->alias('jwt.blacklist', Blacklist::class);
        $this->app->alias('jwt.payload.factory', Factory::class);
        $this->app->alias('jwt.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     *
     * @return void
     */
    protected function registerDriver()
    {
        $this->registerNamshi();
        $this->registerLcobucci();

        $this->app->singleton('jwt.driver', function ($app) {
            return $this->getConfigInstance('driver');
        });
    }

    /**
     * Register the bindings for the Lcobucci.
     *
     * @return void
     */
    protected function registerNamshi()
    {
        $this->app->singleton('jwt.driver.namshi', function ($app) {
            return new Namshi(
                new JWS(['typ' => 'JWT', 'alg' => $this->config('algo')]),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Lcobucci.
     *
     * @return void
     */
    protected function registerLcobucci()
    {
        $this->app->singleton('jwt.driver.lcobucci', function ($app) {
            return new Lcobucci(
                new JWTBuilder(),
                new JWTParser(),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Storage provider.
     *
     * @return void
     */
    protected function registerStorage()
    {
        $this->app->singleton('jwt.storage', function () {
            return $this->getConfigInstance('storage');
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     *
     * @return void
     */
    protected function registerManager()
    {
        $this->app->singleton('jwt.manager', function ($app) {
            $instance = new Manager(
                $app['jwt.driver'],
                $app['jwt.blacklist'],
                $app['jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'))
                            ->setPersistentClaims($this->config('persistent_claims'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     *
     * @return void
     */
    protected function registerParser()
    {
        $this->app->singleton('jwt.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders,
                    new QueryString,
                    new InputSource,
                    new RouteParams,
                    new Cookies($this->config('decrypt_cookies')),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JWT class.
     *
     * @return void
     */
    protected function registerJWT()
    {
        $this->app->singleton('jwt', function ($app) {
            return (new JWT(
                $app['jwt.manager'],
                $app['jwt.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the Blacklist.
     *
     * @return void
     */
    protected function registerBlacklist()
    {
        $this->app->singleton('jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['jwt.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'))
                            ->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     *
     * @return void
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('jwt.validators.payload', function () {
            return (new PayloadValidator)
                ->setRefreshTTL($this->config('refresh_ttl'))
                ->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Claim Factory.
     *
     * @return void
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('jwt.claim.factory', function ($app) {
            $factory = new ClaimFactory($app['request']);
            $app->refresh('request', $factory, 'setRequest');

            return $factory->setTTL($this->config('ttl'))
                           ->setLeeway($this->config('leeway'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     *
     * @return void
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('jwt.payload.factory', function ($app) {
            return new Factory(
                $app['jwt.claim.factory'],
                $app['jwt.validators.payload']
            );
        });
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerCommand()
    {
        $this->app->singleton('jwt.secret', function () {
            return new JWTGenerateSecretCommand;
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  string  $key
     * @param  string  $default
     *
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param  string  $key
     *
     * @return mixed
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
