<?php

namespace Rezzza\SecurityBundle\Security\Firewall;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

// Symfony < 4.3
if (!class_exists(RequestEvent::class)) {
    class RequestSignatureListener implements ListenerInterface
    {
        use RequestSignatureListenerTrait;

        public function handle(GetResponseEvent $event)
        {
            $this->handleOrInvoke($event);
        }
    }
} else {
    class RequestSignatureListener
    {
        use RequestSignatureListenerTrait;

        public function __invoke(RequestEvent $event)
        {
            $this->handleOrInvoke($event);
        }
    }
}
