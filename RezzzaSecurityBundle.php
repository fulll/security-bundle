<?php

namespace Rezzza\SecurityBundle;

use Rezzza\SecurityBundle\DependencyInjection\Security\Factory\RequestSignatureFactory;
use Rezzza\SecurityBundle\DependencyInjection\Compiler;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * RezzzaSecurityBundle
 *
 * @uses Bundle
 * @author Stephane PY <py.stephane1@gmail.com>
 */
class RezzzaSecurityBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addAuthenticatorFactory(new RequestSignatureFactory());

        $container->addCompilerPass(new Compiler\ObfuscatorCompilerPass());
    }
}
