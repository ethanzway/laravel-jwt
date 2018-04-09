<?php

/*
 * This file is part of jwt.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Exceptions;

use Exception;
use Ethanzway\JWT\Claims\Claim;

class InvalidClaimException extends JWTException
{
    /**
     * Constructor.
     *
     * @param  \Ethanzway\JWT\Claims\Claim  $claim
     * @param  int  $code
     * @param  \Exception|null  $previous
     *
     * @return void
     */
    public function __construct(Claim $claim, $code = 0, Exception $previous = null)
    {
        parent::__construct('Invalid value provided for claim ['.$claim->getName().']', $code, $previous);
    }
}
