<?php

/*
 * This file is part of jwt-auth.
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Test\Driver;

use Ethanzway\JWT\Test\AbstractTestCase;
use Ethanzway\JWT\Test\Stubs\DriverStub;

class DriverTest extends AbstractTestCase
{
    /**
     * @var \Ethanzway\JWT\Test\Stubs\DriverStub
     */
    protected $driver;

    public function setUp()
    {
        parent::setUp();

        $this->provider = new DriverStub('secret', 'HS256', []);
    }

    /** @test */
    public function it_should_set_the_algo()
    {
        $this->provider->setAlgo('HS512');

        $this->assertSame('HS512', $this->provider->getAlgo());
    }

    /** @test */
    public function it_should_set_the_secret()
    {
        $this->provider->setSecret('foo');

        $this->assertSame('foo', $this->provider->getSecret());
    }
}
