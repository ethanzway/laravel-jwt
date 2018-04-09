<?php

/*
 * This file is part of jwt.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT;

use Ethanzway\JWT\Support\RefreshFlow;
use Ethanzway\JWT\Support\CustomClaims;
use Ethanzway\JWT\Exceptions\JWTException;
use Ethanzway\JWT\Exceptions\TokenBlacklistedException;
use Ethanzway\JWT\Contracts\Driver;

class Manager
{
    use CustomClaims, RefreshFlow;

    /**
     * The driver.
     *
     * @var \Ethanzway\JWT\Contracts\Driver
     */
    protected $driver;

    /**
     * The blacklist.
     *
     * @var \Ethanzway\JWT\Blacklist
     */
    protected $blacklist;

    /**
     * the payload factory.
     *
     * @var \Ethanzway\JWT\Factory
     */
    protected $payloadFactory;

    /**
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * the persistent claims.
     *
     * @var array
     */
    protected $persistentClaims = [];

    /**
     * Constructor.
     *
     * @param  \Ethanzway\JWT\Contracts\Driver  $driver
     * @param  \Ethanzway\JWT\Blacklist  $blacklist
     * @param  \Ethanzway\JWT\Factory  $payloadFactory
     *
     * @return void
     */
    public function __construct(Driver $driver, Blacklist $blacklist, Factory $payloadFactory)
    {
        $this->driver = $driver;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \Ethanzway\JWT\Payload  $payload
     *
     * @return \Ethanzway\JWT\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->driver->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \Ethanzway\JWT\Token  $token
     * @param  bool  $checkBlacklist
     *
     * @throws \Ethanzway\JWT\Exceptions\TokenBlacklistedException
     *
     * @return \Ethanzway\JWT\Payload
     */
    public function decode(Token $token, $checkBlacklist = true)
    {
        $payloadArray = $this->driver->decode($token->get());

        $payload = $this->payloadFactory
                        ->setRefreshFlow($this->refreshFlow)
                        ->customClaims($payloadArray)
                        ->make();

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \Ethanzway\JWT\Token  $token
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     *
     * @return \Ethanzway\JWT\Token
     */
    public function refresh(Token $token, $forceForever = false, $resetClaims = false)
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token, $forceForever);
        }

        // Return the new token
        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make($resetClaims)
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @param  \Ethanzway\JWT\Token  $token
     * @param  bool  $forceForever
     *
     * @throws \Ethanzway\JWT\Exceptions\JWTException
     *
     * @return bool
     */
    public function invalidate(Token $token, $forceForever = false)
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token, false)
        );
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @param  \Ethanzway\JWT\Payload  $payload
     *
     * @return array
     */
    protected function buildRefreshClaims(Payload $payload)
    {
        // assign the payload values as variables for use later
        extract($payload->toArray());

        // persist the relevant claims
        return array_merge(
            $this->customClaims,
            compact($this->persistentClaims, 'sub', 'iat')
        );
    }

    /**
     * Get the Payload Factory instance.
     *
     * @return \Ethanzway\JWT\Factory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the Driver instance.
     *
     * @return \Ethanzway\JWT\Contracts\Driver
     */
    public function getDriver()
    {
        return $this->driver;
    }

    /**
     * Get the Blacklist instance.
     *
     * @return \Ethanzway\JWT\Blacklist
     */
    public function getBlacklist()
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     * @param  bool  $enabled
     *
     * @return $this
     */
    public function setBlacklistEnabled($enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setPersistentClaims(array $claims)
    {
        $this->persistentClaims = $claims;

        return $this;
    }
}
