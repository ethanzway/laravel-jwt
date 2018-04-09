<?php

/*
 * This file is part of jwt-auth.
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Test\Stubs;

use Ethanzway\JWT\Contracts\Subject;

class UserStub implements Subject
{
    public function getIdentifier()
    {
        return 1;
    }

    public function getCustomClaims()
    {
        return [
            'foo' => 'bar',
            'role' => 'admin',
        ];
    }
}
