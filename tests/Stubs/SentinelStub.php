<?php

/*
 * This file is part of jwt-auth.
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Test\Stubs;

use Cartalyst\Sentinel\Users\UserInterface;

class SentinelStub implements UserInterface
{
    public function getUserId()
    {
        return 123;
    }

    public function getUserLogin()
    {
        return 'foo';
    }

    public function getUserLoginName()
    {
        return 'bar';
    }

    public function getUserPassword()
    {
        return 'baz';
    }
}
