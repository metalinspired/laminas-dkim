<?php

declare(strict_types=1);

namespace Dkim;

use Dkim\Signer\Signer;
use Dkim\Signer\SignerFactory;

final class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->getDependencyConfig(),
        ];
    }

    public function getDependencyConfig(): array
    {
        return [
            'factories' => [
                Signer::class => SignerFactory::class,
            ],
            'aliases'   => [
                'DkimSigner' => Signer::class,
            ],
        ];
    }
}
