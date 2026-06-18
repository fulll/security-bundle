<?php

declare(strict_types=1);

use Rezzza\SecurityBundle\Request\Obfuscator\RequestObfuscator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();
    $parameters = $container->parameters();

    $parameters->set('rezzza.security.request_obfuscator.obfuscator.class', RequestObfuscator::class);

    $services->set('rezzza.security.request_obfuscator.obfuscator', '%rezzza.security.request_obfuscator.obfuscator.class%');
};
