<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\Security\Badge;

use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

class AccountingFirmIdBadge implements BadgeInterface
{
    public function __construct(
        private int $accountingFirmId,
    ) {
    }

    public function getAccountingFirmId(): int
    {
        return $this->accountingFirmId;
    }

    public function isResolved(): bool
    {
        return true;
    }
}
