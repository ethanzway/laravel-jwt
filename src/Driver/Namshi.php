<?php

/*
 * This file is part of jwt.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Driver;

use Exception;
use Namshi\JOSE\JWS;
use ReflectionClass;
use ReflectionException;
use InvalidArgumentException;
use Ethanzway\JWT\Contracts\Driver;
use Namshi\JOSE\Signer\OpenSSL\PublicKey;
use Ethanzway\JWT\Exceptions\JWTException;
use Ethanzway\JWT\Exceptions\TokenInvalidException;

class Namshi extends BaseDriver implements Driver
{
    /**
     * The JWS.
     *
     * @var \Namshi\JOSE\JWS
     */
    protected $jws;

    /**
     * Constructor.
     *
     * @param  \Namshi\JOSE\JWS  $jws
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     *
     * @return void
     */
    public function __construct(JWS $jws, $secret, $algo, array $keys)
    {
        parent::__construct($secret, $algo, $keys);

        $this->jws = $jws;
    }

    /**
     * Create a JSON Web Token.
     *
     * @param  array  $payload
     *
     * @throws \Ethanzway\JWT\Exceptions\JWTException
     *
     * @return string
     */
    public function encode(array $payload)
    {
        try {
            $this->jws->setPayload($payload)->sign($this->getSigningKey(), $this->getPassphrase());

            return (string) $this->jws->getTokenString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     *
     * @throws \Ethanzway\JWT\Exceptions\JWTException
     *
     * @return array
     */
    public function decode($token)
    {
        try {
            // Let's never allow insecure tokens
            $jws = $this->jws->load($token, false);
        } catch (InvalidArgumentException $e) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        if (! $jws->verify($this->getVerificationKey(), $this->getAlgo())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (array) $jws->getPayload();
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        try {
            return (new ReflectionClass(sprintf('Namshi\\JOSE\\Signer\\OpenSSL\\%s', $this->getAlgo())))->isSubclassOf(PublicKey::class);
        } catch (ReflectionException $e) {
            throw new JWTException('The given algorithm could not be found', $e->getCode(), $e);
        }
    }
}
