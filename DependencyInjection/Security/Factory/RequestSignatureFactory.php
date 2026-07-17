<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\DependencyInjection\Security\Factory;

use Rezzza\SecurityBundle\Security\Firewall\AccountingFirmIdBadgeConfig;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * @phpstan-type RequestSignatureConfig array{
 *     algorithm: string,
 *     secret: string,
 *     ignore: bool,
 *     parameter: string,
 *     replay_protection: array{
 *         enabled: bool,
 *         lifetime: int|string,
 *         parameter: string,
 *     },
 *     badges?: array{
 *         accounting_firm_id?: array{
 *             source: 'header'|'query'|'request'|'attribute',
 *             name: string,
 *         },
 *     },
 * }
 */
class RequestSignatureFactory implements AuthenticatorFactoryInterface
{
    /**
     * @param RequestSignatureConfig $config
     */
    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): array|string
    {
        $signatureQueryParametersId = $this->createSignatureQueryParameters($container, $firewallName, $config);
        $signatureConfigId = $this->createSignatureConfig($container, $firewallName, $config);
        $replayProtectionId = $this->createReplayProtection($container, $firewallName, $config);
        $accountingFirmIdBadgeConfigId = $this->createAccountingFirmIdBadgeConfig($container, $firewallName, $config);

        $listenerId = 'security.authentication.listener.request_signature.'.$firewallName;
        $container
            ->setDefinition($listenerId, $this->createDefinition('rezzza.security.request_signature.listener'))
            ->replaceArgument(1, new Reference($signatureQueryParametersId))
            ->replaceArgument(2, $config['ignore'])
            ->replaceArgument(3, new Reference($signatureConfigId))
            ->replaceArgument(4, new Reference($replayProtectionId))
            ->replaceArgument(5, null !== $accountingFirmIdBadgeConfigId ? new Reference($accountingFirmIdBadgeConfigId) : null)
        ;

        return $listenerId;
    }

    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey(): string
    {
        return 'request_signature';
    }

    public function getPriority(): int
    {
        return 0;
    }

    /**
     * @param RequestSignatureConfig $config
     */
    public function createSignatureConfig(ContainerBuilder $container, string $firewallName, array $config): string
    {
        $signatureConfigId = 'rezzza.security.request_signature.signature_config.'.$firewallName;
        $container
            ->setDefinition($signatureConfigId, $this->createDefinition('rezzza.security.request_signature.signature_config'))
            ->addArgument($config['replay_protection']['enabled'])
            ->addArgument($config['algorithm'])
            ->addArgument($config['secret'])
        ;

        return $signatureConfigId;
    }

    /**
     * @param RequestSignatureConfig $config
     */
    public function createSignatureQueryParameters(ContainerBuilder $container, string $firewallName, array $config): string
    {
        $signatureQueryParametersId = 'rezzza.security.request_signature.signature_query_parameters.'.$firewallName;
        $container
            ->setDefinition($signatureQueryParametersId, $this->createDefinition('rezzza.security.request_signature.signature_query_parameters'))
            ->addArgument($config['parameter'])
            ->addArgument($config['replay_protection']['parameter'])
        ;

        return $signatureQueryParametersId;
    }

    /**
     * @param RequestSignatureConfig $config
     */
    public function createReplayProtection(ContainerBuilder $container, string $firewallName, array $config): string
    {
        $replayProtectionId = 'rezzza.security.request_signature.replay_protection.'.$firewallName;
        $container
            ->setDefinition($replayProtectionId, $this->createDefinition('rezzza.security.request_signature.replay_protection'))
            ->addArgument($config['replay_protection']['enabled'])
            ->addArgument($config['replay_protection']['lifetime'])
        ;

        return $replayProtectionId;
    }

    /**
     * @param RequestSignatureConfig $config
     */
    public function createAccountingFirmIdBadgeConfig(ContainerBuilder $container, string $firewallName, array $config): ?string
    {
        if (!isset($config['badges']['accounting_firm_id'])) {
            return null;
        }

        $accountingFirmIdBadgeConfigId = 'rezzza.security.request_signature.accounting_firm_id_badge_config.'.$firewallName;
        $container
            ->setDefinition($accountingFirmIdBadgeConfigId, new Definition(AccountingFirmIdBadgeConfig::class))
            ->addArgument($config['badges']['accounting_firm_id']['source'])
            ->addArgument($config['badges']['accounting_firm_id']['name'])
        ;

        return $accountingFirmIdBadgeConfigId;
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        $node->children()
            ->scalarNode('algorithm')->defaultValue('SHA1')->cannotBeEmpty()->end()
            ->scalarNode('secret')->isRequired()->cannotBeEmpty()->end()
            ->booleanNode('ignore')->defaultFalse()->end()
            ->scalarNode('parameter')->defaultValue('_signature')->cannotBeEmpty()->end()
            ->arrayNode('replay_protection')
                ->addDefaultsIfNotSet()
                ->children()
                    ->booleanNode('enabled')->defaultTrue()->end()
                    ->scalarNode('lifetime')->defaultValue(600)->end()
                    ->scalarNode('parameter')->defaultValue('_signature_time')->cannotBeEmpty()->end()
                ->end()
            ->end()
            ->arrayNode('badges')
                ->beforeNormalization()
                    ->always(static function (mixed $v): mixed {
                        if (\is_array($v) && [] === $v) {
                            throw new InvalidConfigurationException('At least one badge must be configured under "badges" when this section is defined.');
                        }

                        return $v;
                    })
                ->end()
                ->children()
                    ->arrayNode('accounting_firm_id')
                        ->treatNullLike([])
                        ->addDefaultsIfNotSet()
                        ->children()
                            ->enumNode('source')
                                ->values(['header', 'query', 'request', 'attribute'])
                                ->defaultValue('header')
                            ->end()
                            ->scalarNode('name')->defaultValue('X-Accounting-Firm-Id')->cannotBeEmpty()->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;
    }

    private function createDefinition(string $serviceId): ChildDefinition
    {
        return new ChildDefinition($serviceId);
    }
}
