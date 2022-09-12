<?php

declare(strict_types=1);

namespace Dkim\Header;

use Laminas\Mail\Header\Exception\InvalidArgumentException;
use Laminas\Mail\Header\GenericHeader;
use Laminas\Mail\Header\HeaderInterface;

use function strtolower;

/**
 * @see \DkimTest\Header\DkimTest
 */
final class Dkim implements HeaderInterface
{
    public function __construct(private readonly string $value)
    {
    }

    /**
     * {@inheritDoc}
     */
    public static function fromString($headerLine): self
    {
        [$name, $value] = GenericHeader::splitHeaderLine($headerLine);

        // check to ensure proper header type for this factory
        if (strtolower($name) !== 'dkim-signature') {
            throw new InvalidArgumentException('Invalid header line for DKIM-Signature string');
        }

        return new self($value);
    }

    /**
     * {@inheritDoc}
     */
    public function getFieldName(): string
    {
        return 'DKIM-Signature';
    }

    /**
     * {@inheritDoc}
     */
    public function getFieldValue($format = HeaderInterface::FORMAT_RAW): string
    {
        return $this->value;
    }

    /**
     * {@inheritDoc}
     */
    public function setEncoding($encoding): self
    {
        // This header must be always in US-ASCII
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getEncoding(): string
    {
        return 'ASCII';
    }

    /**
     * {@inheritDoc}
     */
    public function toString(): string
    {
        return 'DKIM-Signature: ' . $this->getFieldValue();
    }
}
