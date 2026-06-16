<?php

declare(strict_types=1);

use Rezzza\SecurityBundle\DependencyInjection\Security\Factory\RequestSignatureFactory;
use Rezzza\SecurityBundle\Security\Firewall\ReplayProtection;
use Rezzza\SecurityBundle\Security\Firewall\RequestSignatureListener;
use Rezzza\SecurityBundle\Security\Firewall\RequestSignatureProdiver;
use Rezzza\SecurityBundle\Security\Firewall\SignatureConfig;
use Rezzza\SecurityBundle\Security\Firewall\SignatureQueryParameters;
use Rezzza\SecurityBundle\Security\Listener\CorsSecurityListener;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();
    $parameters = $container->parameters();

    $parameters->set('rezzza.security.request_signature.listener.class', RequestSignatureListener::class);
    $parameters->set('rezzza.security.request_signature.signature_query_parameters.class', SignatureQueryParameters::class);
    $parameters->set('rezzza.security.request_signature.signature_config.class', SignatureConfig::class);
    $parameters->set('rezzza.security.request_signature.replay_protection.class', ReplayProtection::class);

    $services->set('fulll.cors_listener', CorsSecurityListener::class)
        ->private()
        ->args([
            service('logger')->nullOnInvalid(),
        ])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.request',
            'method' => 'onKernelRequest',
            'priority' => 200,
        ]);

    $services->set('fulll.request_signature.provider', RequestSignatureProdiver::class);

    $services->set('rezzza.security.request_signature.listener', '%rezzza.security.request_signature.listener.class%')
        ->private()
        ->args([
            service('security.token_storage'),
            null, // injected via RequestSignatureFactory
            null, // injected via RequestSignatureFactory
            null, // injected via RequestSignatureFactory
            null, // injected via RequestSignatureFactory
        ]);

    $services->set('rezzza.security.request_signature.signature_query_parameters', '%rezzza.security.request_signature.signature_query_parameters.class%')
        ->private();

    $services->set('rezzza.security.request_signature.signature_config', '%rezzza.security.request_signature.signature_config.class%')
        ->private();

    $services->set('rezzza.security.request_signature.replay_protection', '%rezzza.security.request_signature.replay_protection.class%')
        ->private();

    // for 2.0
    $services->set('rezzza.security.request_signature.factory', RequestSignatureFactory::class)
        ->tag('security.listener.factory');
};
