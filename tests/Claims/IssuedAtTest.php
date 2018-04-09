<?php

/*
 * This file is part of jwt-auth.
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Test\Claims;

use Ethanzway\JWT\Claims\IssuedAt;
use Ethanzway\JWT\Test\AbstractTestCase;

class IssuedAtTest extends AbstractTestCase
{
    /**
     * @test
     * @expectedException \Ethanzway\JWT\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [iat]
     */
    public function it_should_throw_an_exception_when_passing_a_future_timestamp()
    {
        new IssuedAt($this->testNowTimestamp + 3600);
    }
}
