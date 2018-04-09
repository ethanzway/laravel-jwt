<?php

/*
 * This file is part of jwt-auth.
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Test\Stubs;

use Ethanzway\JWT\Driver\BaseDriver;

class DriverStub extends BaseDriver
{
    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        return false;
    }
}
