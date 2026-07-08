<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\Security\Firewall;

class AccountingFirmIdBadgeConfig
{
    public function __construct(
        private string $source,
        private string $name,
    ) {
    }

    public function getSource(): string
    {
        return $this->source;
    }

    public function getName(): string
    {
        return $this->name;
    }
}
