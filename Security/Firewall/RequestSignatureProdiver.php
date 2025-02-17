<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\Security\Firewall;

use Rezzza\SecurityBundle\Security\SignatureValidUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class RequestSignatureProdiver implements UserProviderInterface
{
    public function loadUserByUsername($username): UserInterface
    {
        throw new \LogicException(sprintf('Method %s should never be called.', __METHOD__));
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        throw new \LogicException(sprintf('Method %s should never be called.', __METHOD__));
    }

    /**
     * We have not to refresh the user.
     *
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        return $user;
    }

    public function supportsClass($class): bool
    {
        return SignatureValidUser::class === $class;
    }
}
