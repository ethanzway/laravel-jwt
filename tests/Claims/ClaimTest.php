<?php

/*
 * This file is part of jwt-auth.
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Test\Claims;

use Ethanzway\JWT\Claims\Expiration;
use Ethanzway\JWT\Test\AbstractTestCase;
use Illuminate\Contracts\Support\Arrayable;

class ClaimTest extends AbstractTestCase
{
    /**
     * @var \Ethanzway\JWT\Claims\Expiration
     */
    protected $claim;

    public function setUp()
    {
        parent::setUp();

        $this->claim = new Expiration($this->testNowTimestamp);
    }

    /**
     * @test
     * @expectedException \Ethanzway\JWT\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [exp]
     */
    public function it_should_throw_an_exception_when_passing_an_invalid_value()
    {
        $this->claim->setValue('foo');
    }

    /** @test */
    public function it_should_convert_the_claim_to_an_array()
    {
        $this->assertSame(['exp' => $this->testNowTimestamp], $this->claim->toArray());
    }

    /** @test */
    public function it_should_get_the_claim_as_a_string()
    {
        $this->assertJsonStringEqualsJsonString((string) $this->claim, $this->claim->toJson());
    }

    /** @test */
    public function it_should_get_the_object_as_json()
    {
        $this->assertJsonStringEqualsJsonString(json_encode($this->claim), $this->claim->toJson());
    }

    /** @test */
    public function it_should_implement_arrayable()
    {
        $this->assertInstanceOf(Arrayable::class, $this->claim);
    }
}