<?php

/*
 * This file is part of jwt.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Validators;

use Ethanzway\JWT\Claims\Collection;
use Ethanzway\JWT\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    /**
     * The refresh TTL.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * Run the validations on the payload array.
     *
     * @param  \Ethanzway\JWT\Claims\Collection  $value
     *
     * @return \Ethanzway\JWT\Claims\Collection
     */
    public function check($value)
    {
        $this->validateStructure($value);

        return $this->refreshFlow ? $this->validateRefresh($value) : $this->validatePayload($value);
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @param  \Ethanzway\JWT\Claims\Collection  $claims
     *
     * @throws \Ethanzway\JWT\Exceptions\TokenInvalidException
     *
     * @return void
     */
    protected function validateStructure(Collection $claims)
    {
        if (! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
    }

    /**
     * Validate the payload timestamps.
     *
     * @param  \Ethanzway\JWT\Claims\Collection  $claims
     *
     * @throws \Ethanzway\JWT\Exceptions\TokenExpiredException
     * @throws \Ethanzway\JWT\Exceptions\TokenInvalidException
     *
     * @return \Ethanzway\JWT\Claims\Collection
     */
    protected function validatePayload(Collection $claims)
    {
        return $claims->validate('payload');
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @param  \Ethanzway\JWT\Claims\Collection  $claims
     *
     * @throws \Ethanzway\JWT\Exceptions\TokenExpiredException
     *
     * @return \Ethanzway\JWT\Claims\Collection
     */
    protected function validateRefresh(Collection $claims)
    {
        return $this->refreshTTL === null ? $claims : $claims->validate('refresh', $this->refreshTTL);
    }

    /**
     * Set the required claims.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
