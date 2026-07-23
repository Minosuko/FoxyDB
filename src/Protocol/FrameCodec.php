<?php

declare(strict_types=1);

namespace FoxyDB\Protocol;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Value\BinaryValue;

final class FrameCodec
{
    public const HEADER_BYTES = 16;
    public const VERSION = 2;
    public const MAXIMUM_FRAME_BYTES = 16_777_216;

    private const MAGIC = 'FXDB';
    private const KIND_VALUE = 1;
    private const MAXIMUM_DEPTH = 64;
    private const MAXIMUM_CONTAINER_ITEMS = 65_536;
    private const MAXIMUM_AGGREGATE_ITEMS = 100_000;
    private const MAXIMUM_KEY_BYTES = 1_024;
    private const UINT32_BASE = 4_294_967_296;
    private const NULL = 0;
    private const FALSE = 1;
    private const TRUE = 2;
    private const INTEGER = 3;
    private const FLOAT = 4;
    private const TEXT = 5;
    private const BYTES = 6;
    private const LIST = 7;
    private const MAP = 8;

    public static function encode(array $payload, int $maximumBytes): string
    {
        self::require64BitIntegers();
        if ($maximumBytes < 1 || $maximumBytes > self::MAXIMUM_FRAME_BYTES) {
            throw new FoxyException('Invalid protocol frame limit.', 'INVALID_CONFIG');
        }
        if ($payload === [] || array_is_list($payload)) {
            throw new FoxyException('Protocol frames require a non-empty map.', 'PROTOCOL_ERROR');
        }
        $remaining = self::MAXIMUM_AGGREGATE_ITEMS;
        $body = self::encodeValue($payload, 0, $remaining, $maximumBytes);
        if (strlen($body) > $maximumBytes) {
            throw new FoxyException('Protocol frame exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        $prefix = self::MAGIC . chr(self::VERSION) . chr(self::KIND_VALUE) . pack('nN', 0, strlen($body));
        return $prefix . hash('crc32c', $prefix . $body, true) . $body;
    }

    public static function extract(string &$buffer, int $maximumBytes): ?array
    {
        self::require64BitIntegers();
        if (strlen($buffer) < 4) {
            return null;
        }
        if (substr($buffer, 0, 4) !== self::MAGIC) {
            throw new FoxyException('Invalid binary protocol header.', 'PROTOCOL_ERROR');
        }
        if (strlen($buffer) < self::HEADER_BYTES) {
            return null;
        }
        $header = substr($buffer, 0, self::HEADER_BYTES);
        $length = self::payloadLength($header, $maximumBytes);
        if (strlen($buffer) < self::HEADER_BYTES + $length) {
            return null;
        }
        $body = substr($buffer, self::HEADER_BYTES, $length);
        self::verifyChecksum($header, $body);
        $payload = self::decodeRoot($body, $maximumBytes);
        $buffer = substr($buffer, self::HEADER_BYTES + $length);
        return $payload;
    }

    public static function write($stream, array $payload, int $maximumBytes): void
    {
        if (!is_resource($stream)) {
            throw new FoxyException('Client is not connected.', 'CONNECTION_CLOSED');
        }
        $frame = self::encode($payload, $maximumBytes);
        $offset = 0;
        $length = strlen($frame);
        while ($offset < $length) {
            $written = @fwrite($stream, $offset === 0 ? $frame : substr($frame, $offset));
            if ($written === false || $written === 0) {
                self::throwStreamError($stream, 'write');
            }
            $offset += $written;
        }
        if (!@fflush($stream)) {
            throw new FoxyException('Unable to flush the connection.', 'CONNECTION_IO');
        }
    }

    public static function read($stream, int $maximumBytes): array
    {
        self::require64BitIntegers();
        if (!is_resource($stream)) {
            throw new FoxyException('Client is not connected.', 'CONNECTION_CLOSED');
        }
        $header = self::readExact($stream, self::HEADER_BYTES);
        $length = self::payloadLength($header, $maximumBytes);
        $body = self::readExact($stream, $length, true);
        self::verifyChecksum($header, $body);
        return self::decodeRoot($body, $maximumBytes);
    }

    public static function encodedValueBytes(mixed $value, int $maximumBytes = 1_073_741_824): int
    {
        self::require64BitIntegers();
        $remaining = self::MAXIMUM_AGGREGATE_ITEMS;
        return strlen(self::encodeValue($value, 0, $remaining, $maximumBytes));
    }

    private static function encodeValue(mixed $value, int $depth, int &$remaining, int $maximumBytes): string
    {
        if ($depth > self::MAXIMUM_DEPTH) {
            throw new FoxyException('Protocol value exceeds the nesting limit.', 'PROTOCOL_ERROR');
        }
        if ($value === null) {
            return chr(self::NULL);
        }
        if ($value === false) {
            return chr(self::FALSE);
        }
        if ($value === true) {
            return chr(self::TRUE);
        }
        if (is_int($value)) {
            return chr(self::INTEGER) . pack('NN', ($value >> 32) & 0xffffffff, $value & 0xffffffff);
        }
        if (is_float($value)) {
            if (!is_finite($value)) {
                throw new FoxyException('Protocol floats must be finite.', 'PROTOCOL_ERROR');
            }
            return chr(self::FLOAT) . pack('E', $value);
        }
        if (is_string($value)) {
            self::utf8($value, 'Protocol text is not valid UTF-8.');
            return self::scalar(self::TEXT, $value, $maximumBytes);
        }
        if ($value instanceof BinaryValue) {
            return self::scalar(self::BYTES, $value->bytes, $maximumBytes);
        }
        if (!is_array($value)) {
            throw new FoxyException('Protocol value has an unsupported type.', 'PROTOCOL_ERROR');
        }
        $count = count($value);
        if ($count > self::MAXIMUM_CONTAINER_ITEMS || $count > $remaining) {
            throw new FoxyException('Protocol value contains too many items.', 'PROTOCOL_ERROR');
        }
        $remaining -= $count;
        if (array_is_list($value)) {
            $encoded = chr(self::LIST) . pack('N', $count);
            foreach ($value as $item) {
                self::append($encoded, self::encodeValue($item, $depth + 1, $remaining, $maximumBytes), $maximumBytes);
            }
            return $encoded;
        }
        $encoded = chr(self::MAP) . pack('N', $count);
        foreach ($value as $key => $item) {
            if (!is_string($key) || $key === '' || self::numericKey($key)) {
                throw new FoxyException('Protocol map keys must be non-numeric strings.', 'PROTOCOL_ERROR');
            }
            self::utf8($key, 'Protocol map key is not valid UTF-8.');
            if (strlen($key) > self::MAXIMUM_KEY_BYTES) {
                throw new FoxyException('Protocol map key exceeds its limit.', 'PROTOCOL_ERROR');
            }
            self::append($encoded, pack('N', strlen($key)) . $key, $maximumBytes);
            self::append($encoded, self::encodeValue($item, $depth + 1, $remaining, $maximumBytes), $maximumBytes);
        }
        return $encoded;
    }

    private static function decodeRoot(string $body, int $maximumBytes): array
    {
        if ($body === '' || ord($body[0]) !== self::MAP) {
            throw new FoxyException('Protocol frame payload must be a map.', 'PROTOCOL_ERROR');
        }
        $offset = 0;
        $remaining = self::MAXIMUM_AGGREGATE_ITEMS;
        $value = self::decodeValue($body, $offset, 0, $remaining, $maximumBytes);
        if (!is_array($value) || $value === [] || array_is_list($value) || $offset !== strlen($body)) {
            throw new FoxyException('Protocol frame payload is invalid or has trailing data.', 'PROTOCOL_ERROR');
        }
        return $value;
    }

    private static function decodeValue(
        string $body,
        int &$offset,
        int $depth,
        int &$remaining,
        int $maximumBytes,
    ): mixed {
        if ($depth > self::MAXIMUM_DEPTH || $offset >= strlen($body)) {
            throw new FoxyException('Protocol value is truncated or too deeply nested.', 'PROTOCOL_ERROR');
        }
        $tag = ord($body[$offset++]);
        if ($tag === self::NULL) {
            return null;
        }
        if ($tag === self::FALSE || $tag === self::TRUE) {
            return $tag === self::TRUE;
        }
        if ($tag === self::INTEGER) {
            return self::integer(self::take($body, $offset, 8));
        }
        if ($tag === self::FLOAT) {
            $decoded = unpack('Evalue', self::take($body, $offset, 8));
            $value = $decoded['value'] ?? NAN;
            if (!is_float($value) || !is_finite($value)) {
                throw new FoxyException('Protocol float is invalid.', 'PROTOCOL_ERROR');
            }
            return $value;
        }
        if ($tag === self::TEXT || $tag === self::BYTES) {
            $length = self::u32($body, $offset);
            if ($length > $maximumBytes) {
                throw new FoxyException('Protocol scalar exceeds the configured limit.', 'FRAME_TOO_LARGE');
            }
            $value = self::take($body, $offset, $length);
            if ($tag === self::TEXT) {
                self::utf8($value, 'Protocol text is not valid UTF-8.');
                return $value;
            }
            return new BinaryValue($value);
        }
        if ($tag !== self::LIST && $tag !== self::MAP) {
            throw new FoxyException('Protocol value has an unknown type tag.', 'PROTOCOL_ERROR');
        }
        $count = self::u32($body, $offset);
        if ($count > self::MAXIMUM_CONTAINER_ITEMS || $count > $remaining) {
            throw new FoxyException('Protocol value contains too many items.', 'PROTOCOL_ERROR');
        }
        $remaining -= $count;
        if ($tag === self::LIST) {
            $list = [];
            for ($index = 0; $index < $count; $index++) {
                $list[] = self::decodeValue($body, $offset, $depth + 1, $remaining, $maximumBytes);
            }
            return $list;
        }
        if ($count === 0) {
            throw new FoxyException('Empty protocol maps are not supported.', 'PROTOCOL_ERROR');
        }
        $map = [];
        $seen = [];
        for ($index = 0; $index < $count; $index++) {
            $keyLength = self::u32($body, $offset);
            if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                throw new FoxyException('Protocol map key exceeds its limit.', 'PROTOCOL_ERROR');
            }
            $key = self::take($body, $offset, $keyLength);
            self::utf8($key, 'Protocol map key is not valid UTF-8.');
            if ($key === '' || self::numericKey($key) || isset($seen["\0" . $key])) {
                throw new FoxyException('Protocol map key is empty, numeric, or duplicated.', 'PROTOCOL_ERROR');
            }
            $seen["\0" . $key] = true;
            $map[$key] = self::decodeValue($body, $offset, $depth + 1, $remaining, $maximumBytes);
        }
        return $map;
    }

    private static function payloadLength(string $header, int $maximumBytes): int
    {
        if ($maximumBytes < 1 || $maximumBytes > self::MAXIMUM_FRAME_BYTES) {
            throw new FoxyException('Invalid protocol frame limit.', 'INVALID_CONFIG');
        }
        if (strlen($header) !== self::HEADER_BYTES || substr($header, 0, 4) !== self::MAGIC
            || ord($header[4]) !== self::VERSION || ord($header[5]) !== self::KIND_VALUE) {
            throw new FoxyException('Invalid binary protocol header.', 'PROTOCOL_ERROR');
        }
        $fields = unpack('nflags/Nlength', substr($header, 6, 6));
        $length = (int) ($fields['length'] ?? -1);
        if (($fields['flags'] ?? -1) !== 0 || $length < 5) {
            throw new FoxyException('Invalid binary protocol flags or length.', 'PROTOCOL_ERROR');
        }
        if ($length > $maximumBytes) {
            throw new FoxyException('Protocol frame exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        return $length;
    }

    private static function verifyChecksum(string $header, string $body): void
    {
        if (!hash_equals(substr($header, 12, 4), hash('crc32c', substr($header, 0, 12) . $body, true))) {
            throw new FoxyException('Binary protocol checksum mismatch.', 'PROTOCOL_ERROR');
        }
    }

    private static function scalar(int $tag, string $value, int $maximumBytes): string
    {
        if (strlen($value) > $maximumBytes) {
            throw new FoxyException('Protocol scalar exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        return chr($tag) . pack('N', strlen($value)) . $value;
    }

    private static function append(string &$target, string $value, int $maximumBytes): void
    {
        if (strlen($value) > $maximumBytes - strlen($target)) {
            throw new FoxyException('Protocol frame exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        $target .= $value;
    }

    private static function u32(string $body, int &$offset): int
    {
        $decoded = unpack('Nvalue', self::take($body, $offset, 4));
        return (int) ($decoded['value'] ?? 0);
    }

    private static function take(string $body, int &$offset, int $length): string
    {
        if ($length < 0 || $length > strlen($body) - $offset) {
            throw new FoxyException('Protocol value is truncated.', 'PROTOCOL_ERROR');
        }
        $value = substr($body, $offset, $length);
        $offset += $length;
        return $value;
    }

    private static function integer(string $bytes): int
    {
        $parts = unpack('Nhigh/Nlow', $bytes);
        $high = (int) ($parts['high'] ?? 0);
        $low = (int) ($parts['low'] ?? 0);
        if (($high & 0x80000000) === 0) {
            return (int) ($high * self::UINT32_BASE + $low);
        }
        if ($high === 0x80000000 && $low === 0) {
            return PHP_INT_MIN;
        }
        return -(int) ((0xffffffff - $high) * self::UINT32_BASE + (0xffffffff - $low) + 1);
    }

    private static function utf8(string $value, string $message): void
    {
        if (preg_match('//u', $value) !== 1) {
            throw new FoxyException($message, 'PROTOCOL_ERROR');
        }
    }

    private static function numericKey(string $key): bool
    {
        return preg_match('/^(?:0|-?[1-9][0-9]*)$/', $key) === 1;
    }

    private static function require64BitIntegers(): void
    {
        if (PHP_INT_SIZE < 8) {
            throw new FoxyException('Binary protocol version 2 requires 64-bit PHP.', 'INVALID_CONFIG');
        }
    }

    private static function readExact($stream, int $length, bool $frameStarted = false): string
    {
        $data = '';
        $read = 0;
        while ($read < $length) {
            $part = @fread($stream, $length - $read);
            if ($part === false) {
                throw new FoxyException('Unable to read from the connection.', 'CONNECTION_IO');
            }
            if ($part === '') {
                self::throwStreamError($stream, 'read', $frameStarted || $data !== '');
            }
            $data .= $part;
            $read += strlen($part);
        }
        return $data;
    }

    private static function throwStreamError($stream, string $operation, bool $partialFrame = false): never
    {
        $metadata = stream_get_meta_data($stream);
        if (($metadata['timed_out'] ?? false) === true) {
            throw new FoxyException("Connection {$operation} timed out.", 'CONNECTION_TIMEOUT');
        }
        if (feof($stream)) {
            throw new FoxyException(
                $partialFrame ? 'Connection closed during a frame.' : 'Connection was closed.',
                $partialFrame ? 'PROTOCOL_ERROR' : 'CONNECTION_CLOSED',
            );
        }
        throw new FoxyException("Unable to {$operation} the connection.", 'CONNECTION_IO');
    }
}
