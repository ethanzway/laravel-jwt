<?php

/*
 * This file is part of jwt.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Claims;

class JwtId extends Claim
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'jti';
}
