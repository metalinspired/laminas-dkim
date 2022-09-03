<?php

declare(strict_types=1);

namespace Dkim;

/**
 * @see \DkimTest\ModuleTest
 */
final class Module
{
    public function getConfig(): array
    {
        $provider = new ConfigProvider();

        return [
            'service_manager' => $provider->getDependencyConfig(),
        ];
    }
}
