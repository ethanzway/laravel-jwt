<?php

/*
 * This file is part of jwt-auth.
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ethanzway\JWT\Test\Claims;

use Mockery;
use DateTime;
use DateInterval;
use Carbon\Carbon;
use DateTimeImmutable;
use DateTimeInterface;
use Ethanzway\JWT\Payload;
use Ethanzway\JWT\Claims\JwtId;
use Ethanzway\JWT\Claims\Issuer;
use Ethanzway\JWT\Claims\Subject;
use Ethanzway\JWT\Claims\IssuedAt;
use Ethanzway\JWT\Claims\NotBefore;
use Ethanzway\JWT\Claims\Collection;
use Ethanzway\JWT\Claims\Expiration;
use Ethanzway\JWT\Test\AbstractTestCase;
use Ethanzway\JWT\Validators\PayloadValidator;

class DatetimeClaimTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Ethanzway\JWT\Validators\PayloadValidator
     */
    protected $validator;

    /**
     * @var array
     */
    protected $claimsTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check');

        $this->claimsTimestamp = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($this->testNowTimestamp + 3600),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];
    }

    /** @test */
    public function it_should_handle_carbon_claims()
    {
        $testCarbon = Carbon::createFromTimestampUTC($this->testNowTimestamp);
        $testCarbonCopy = clone $testCarbon;

        $this->assertInstanceOf(Carbon::class, $testCarbon);
        $this->assertInstanceOf(Datetime::class, $testCarbon);
        $this->assertInstanceOf(DatetimeInterface::class, $testCarbon);

        $claimsDatetime = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testCarbonCopy->addHour()),
            'nbf' => new NotBefore($testCarbon),
            'iat' => new IssuedAt($testCarbon),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /** @test */
    public function it_should_handle_datetime_claims()
    {
        $testDateTime = DateTime::createFromFormat('U', $this->testNowTimestamp);
        $testDateTimeCopy = clone $testDateTime;

        $this->assertInstanceOf(DateTime::class, $testDateTime);
        $this->assertInstanceOf(DatetimeInterface::class, $testDateTime);

        $claimsDatetime = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateTimeCopy->modify('+3600 seconds')),
            'nbf' => new NotBefore($testDateTime),
            'iat' => new IssuedAt($testDateTime),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /** @test */
    public function it_should_handle_datetime_immutable_claims()
    {
        $testDateTimeImmutable = DateTimeImmutable::createFromFormat('U', (string) $this->testNowTimestamp);

        $this->assertInstanceOf(DateTimeImmutable::class, $testDateTimeImmutable);
        $this->assertInstanceOf(DatetimeInterface::class, $testDateTimeImmutable);

        $claimsDatetime = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateTimeImmutable->modify('+3600 seconds')),
            'nbf' => new NotBefore($testDateTimeImmutable),
            'iat' => new IssuedAt($testDateTimeImmutable),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDatetime = new Payload(Collection::make($claimsDatetime), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDatetime);
    }

    /** @test */
    public function it_should_handle_datetinterval_claims()
    {
        $testDateInterval = DateInterval::createFromDateString('PT1H');

        $this->assertInstanceOf(DateInterval::class, $testDateInterval);

        $claimsDateInterval = [
            'sub' => new Subject(1),
            'iss' => new Issuer('http://example.com'),
            'exp' => new Expiration($testDateInterval),
            'nbf' => new NotBefore($this->testNowTimestamp),
            'iat' => new IssuedAt($this->testNowTimestamp),
            'jti' => new JwtId('foo'),
        ];

        $payloadTimestamp = new Payload(Collection::make($this->claimsTimestamp), $this->validator);
        $payloadDateInterval = new Payload(Collection::make($claimsDateInterval), $this->validator);

        $this->assertEquals($payloadTimestamp, $payloadDateInterval);
    }
}
