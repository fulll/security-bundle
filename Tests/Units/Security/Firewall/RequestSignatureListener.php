<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\Tests\Units\Security\Firewall;

use atoum\atoum;
use Rezzza\SecurityBundle\Security\Badge\AccountingFirmIdBadge;
use Rezzza\SecurityBundle\Security\Firewall\AccountingFirmIdBadgeConfig;
use Rezzza\SecurityBundle\Security\Firewall\ReplayProtection;
use Rezzza\SecurityBundle\Security\Firewall\RequestSignatureListener as SUT;
use Rezzza\SecurityBundle\Security\Firewall\SignatureConfig;
use Rezzza\SecurityBundle\Security\Firewall\SignatureQueryParameters;
use Rezzza\SecurityBundle\Security\Firewall\SignedRequest;
use Rezzza\SecurityBundle\Security\SignatureValidToken;
use Rezzza\SecurityBundle\Security\SignatureValidUser;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class RequestSignatureListener extends atoum\test
{
    private const SECRET = 's3cr3t';

    public function test_authenticate_adds_accounting_firm_id_badge_when_value_present_in_header(): void
    {
        $this
            ->given(
                $request = $this->buildSignedRequest(['X-Accounting-Firm-Id' => '42']),
                $sut = $this->buildListener(new AccountingFirmIdBadgeConfig('header', 'X-Accounting-Firm-Id')),
            )
            ->when(
                $passport = $sut->authenticate($request),
            )
            ->then
                ->boolean($passport->hasBadge(AccountingFirmIdBadge::class))
                    ->isTrue()
                ->integer($passport->getBadge(AccountingFirmIdBadge::class)->getAccountingFirmId())
                    ->isEqualTo(42)
        ;
    }

    public function test_authenticate_adds_accounting_firm_id_badge_when_value_present_in_query(): void
    {
        $this
            ->given(
                $request = $this->buildSignedRequest([], ['accounting_firm_id' => '42']),
                $sut = $this->buildListener(new AccountingFirmIdBadgeConfig('query', 'accounting_firm_id')),
            )
            ->when(
                $passport = $sut->authenticate($request),
            )
            ->then
                ->boolean($passport->hasBadge(AccountingFirmIdBadge::class))
                    ->isTrue()
                ->integer($passport->getBadge(AccountingFirmIdBadge::class)->getAccountingFirmId())
                    ->isEqualTo(42)
        ;
    }

    public function test_authenticate_does_not_add_badge_when_not_configured(): void
    {
        $this
            ->given(
                $request = $this->buildSignedRequest(),
                $sut = $this->buildListener(null),
            )
            ->when(
                $passport = $sut->authenticate($request),
            )
            ->then
                ->boolean($passport->hasBadge(AccountingFirmIdBadge::class))
                    ->isFalse()
        ;
    }

    public function test_authenticate_rejects_when_accounting_firm_id_missing(): void
    {
        $this
            ->given(
                $request = $this->buildSignedRequest(),
                $sut = $this->buildListener(new AccountingFirmIdBadgeConfig('header', 'X-Accounting-Firm-Id')),
            )
            ->exception(static function () use ($sut, $request): void {
                $sut->authenticate($request);
            })
                ->isInstanceOf('Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException')
        ;
    }

    public function test_authenticate_rejects_when_accounting_firm_id_not_numeric(): void
    {
        $this
            ->given(
                $request = $this->buildSignedRequest(['X-Accounting-Firm-Id' => 'abc']),
                $sut = $this->buildListener(new AccountingFirmIdBadgeConfig('header', 'X-Accounting-Firm-Id')),
            )
            ->exception(static function () use ($sut, $request): void {
                $sut->authenticate($request);
            })
                ->isInstanceOf('Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException')
        ;
    }

    public function test_createToken_injects_accounting_firm_id_from_badge(): void
    {
        $this
            ->given(
                $sut = $this->buildListener(new AccountingFirmIdBadgeConfig('header', 'X-Accounting-Firm-Id')),
                $passport = new SelfValidatingPassport(
                    new UserBadge('signature', static fn () => new SignatureValidUser()),
                ),
                $passport->addBadge(new AccountingFirmIdBadge(42)),
            )
            ->when(
                $token = $sut->createToken($passport, 'main'),
            )
            ->then
                ->object($token)
                    ->isInstanceOf(SignatureValidToken::class)
                ->integer($token->getAccountingFirmId())
                    ->isEqualTo(42)
        ;
    }

    public function test_createToken_leaves_accounting_firm_id_null_when_no_badge(): void
    {
        $this
            ->given(
                $sut = $this->buildListener(null),
                $passport = new SelfValidatingPassport(
                    new UserBadge('signature', static fn () => new SignatureValidUser()),
                ),
            )
            ->when(
                $token = $sut->createToken($passport, 'main'),
            )
            ->then
                ->variable($token->getAccountingFirmId())
                    ->isNull()
        ;
    }

    private function buildListener(?AccountingFirmIdBadgeConfig $accountingFirmIdBadgeConfig): SUT
    {
        return new SUT(
            new \mock\Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface(),
            new SignatureQueryParameters('_signature', '_signature_time'),
            false,
            new SignatureConfig(false, 'sha1', self::SECRET),
            new ReplayProtection(false, 0),
            $accountingFirmIdBadgeConfig,
        );
    }

    private function buildSignedRequest(array $headers = [], array $extraQuery = []): Request
    {
        $method = 'GET';
        $host = 'localhost';
        $path = '/url';
        $content = '';

        $signatureConfig = new SignatureConfig(false, 'sha1', self::SECRET);
        $signature = (new SignedRequest($method, $host, $path, $content))->buildSignature($signatureConfig, true);

        $query = array_merge(['_signature' => $signature], $extraQuery);

        $request = Request::create('http://'.$host.$path, $method, $query);

        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value);
        }

        return $request;
    }
}
