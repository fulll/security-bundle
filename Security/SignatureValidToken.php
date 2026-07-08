<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\Security;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class SignatureValidToken extends AbstractToken
{
    public function __construct(
        SignatureValidUser $user,
        private ?int $accountingFirmId = null,
    ) {
        parent::__construct();
        $this->setUser($user);
    }

    public function getCredentials(): string
    {
        return '';
    }

    public function getAccountingFirmId(): ?int
    {
        return $this->accountingFirmId;
    }
}
