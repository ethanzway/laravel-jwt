<?php

/*
 * This file is part of jwt.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT;

use Ethanzway\JWT\Claims\Claim;
use Ethanzway\JWT\Claims\Collection;
use Ethanzway\JWT\Support\RefreshFlow;
use Ethanzway\JWT\Support\CustomClaims;
use Ethanzway\JWT\Validators\PayloadValidator;
use Ethanzway\JWT\Claims\Factory as ClaimFactory;

class Factory
{
    use CustomClaims, RefreshFlow;

    /**
     * The claim factory.
     *
     * @var \Ethanzway\JWT\Claims\Factory
     */
    protected $claimFactory;

    /**
     * The validator.
     *
     * @var \Ethanzway\JWT\Validators\PayloadValidator
     */
    protected $validator;

    /**
     * The default claims.
     *
     * @var array
     */
    protected $defaultClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'jti',
    ];

    /**
     * The claims collection.
     *
     * @var \Ethanzway\JWT\Claims\Collection
     */
    protected $claims;

    /**
     * Constructor.
     *
     * @param  \Ethanzway\JWT\Claims\Factory  $claimFactory
     * @param  \Ethanzway\JWT\Validators\PayloadValidator  $validator
     *
     * @return void
     */
    public function __construct(ClaimFactory $claimFactory, PayloadValidator $validator)
    {
        $this->claimFactory = $claimFactory;
        $this->validator = $validator;
        $this->claims = new Collection;
    }

    /**
     * Create the Payload instance.
     *
     * @param  bool  $resetClaims
     *
     * @return \Ethanzway\JWT\Payload
     */
    public function make($resetClaims = false)
    {
        $payload = $this->withClaims($this->buildClaimsCollection());

        if ($resetClaims) {
            $this->emptyClaims();
        }

        return $payload;
    }

    /**
     * Empty the claims collection.
     *
     * @return $this
     */
    public function emptyClaims()
    {
        $this->claims = new Collection;

        return $this;
    }

    /**
     * Add an array of claims to the Payload.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    protected function addClaims(array $claims)
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    /**
     * Add a claim to the Payload.
     *
     * @param  string  $name
     * @param  mixed  $value
     *
     * @return $this
     */
    protected function addClaim($name, $value)
    {
        $this->claims->put($name, $value);

        return $this;
    }

    /**
     * Build the default claims.
     *
     * @return $this
     */
    protected function buildClaims()
    {
        // remove the exp claim if it exists and the ttl is null
        if ($this->claimFactory->getTTL() === null && $key = array_search('exp', $this->defaultClaims)) {
            unset($this->defaultClaims[$key]);
        }

        // add the default claims
        foreach ($this->defaultClaims as $claim) {
            $this->addClaim($claim, $this->claimFactory->make($claim));
        }

        // add custom claims on top, allowing them to overwrite defaults
        return $this->addClaims($this->getCustomClaims());
    }

    /**
     * Build out the Claim DTO's.
     *
     * @return \Ethanzway\JWT\Claims\Collection
     */
    protected function resolveClaims()
    {
        return $this->claims->map(function ($value, $name) {
            return $value instanceof Claim ? $value : $this->claimFactory->get($name, $value);
        });
    }

    /**
     * Build and get the Claims Collection.
     *
     * @return \Ethanzway\JWT\Claims\Collection
     */
    public function buildClaimsCollection()
    {
        return $this->buildClaims()->resolveClaims();
    }

    /**
     * Get a Payload instance with a claims collection.
     *
     * @param  \Ethanzway\JWT\Claims\Collection  $claims
     *
     * @return \Ethanzway\JWT\Payload
     */
    public function withClaims(Collection $claims)
    {
        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    /**
     * Set the default claims to be added to the Payload.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setDefaultClaims(array $claims)
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Helper to set the ttl.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->claimFactory->setTTL($ttl);

        return $this;
    }

    /**
     * Helper to get the ttl.
     *
     * @return int
     */
    public function getTTL()
    {
        return $this->claimFactory->getTTL();
    }

    /**
     * Get the default claims.
     *
     * @return array
     */
    public function getDefaultClaims()
    {
        return $this->defaultClaims;
    }

    /**
     * Get the PayloadValidator instance.
     *
     * @return \Ethanzway\JWT\Validators\PayloadValidator
     */
    public function validator()
    {
        return $this->validator;
    }

    /**
     * Magically add a claim.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @return $this
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
