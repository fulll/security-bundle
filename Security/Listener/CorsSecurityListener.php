<?php

declare(strict_types=1);

namespace Rezzza\SecurityBundle\Security\Listener;

use Nelmio\CorsBundle\EventListener\CorsListener;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Deny request if Origin header is set and nelmio/cors-bundle has rejected it.
 */
class CorsSecurityListener
{
    private LoggerInterface|NullLogger $logger;

    public function __construct(
        ?LoggerInterface $logger,
    ) {
        if (null === $logger) {
            $logger = new NullLogger();
        }

        $this->logger = $logger;
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (HttpKernelInterface::MAIN_REQUEST !== $event->getRequestType()) {
            $this->logger->debug('Not a master type request, skipping CORS validation.');

            return;
        }

        $request = $event->getRequest();

        // CORS preflight request was already handled by NelmioCorsBundle
        if ('OPTIONS' === $request->getMethod()) {
            return;
        }

        // If Origin header was the same as the request host, we can skip CORS validation
        if ($request->headers->get('Origin') === $request->getSchemeAndHttpHost()) {
            return;
        }

        // If the request has an Origin header and the CORS listener has not validated it, deny the request
        if (
            $request->headers->has('Origin')
            && !$request->attributes->has(CorsListener::SHOULD_ALLOW_ORIGIN_ATTR)
        ) {
            $this->logger->debug('CORS validation failed, denying request.');

            $response = new Response('Origin CORS denied', Response::HTTP_BAD_REQUEST);
            $event->setResponse($response);
        }
    }
}
