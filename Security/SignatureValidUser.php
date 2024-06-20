<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

class SignatureValidUser implements UserInterface
{
    public function getRoles(): array
    {
        return [];
    }

    public function getPassword(): ?string
    {
        return null;
    }

    public function getSalt(): ?string
    {
        return null;
    }

    public function eraseCredentials(): void
    {
    }

    public function getUsername(): ?string
    {
        return '';
    }

    public function getUserIdentifier(): string
    {
        return '';
    }
}
