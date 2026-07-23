<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Value\BinaryValue;

final class Client
{
    private const PROTOCOL_VERSION = FrameCodec::VERSION;
    private int $nextRequestId = 1;
    private array $serverInfo = [];
    private ?string $authenticatedUsername = null;
    private ?string $currentDatabase = null;

    private function __construct(
        private $stream,
        private readonly string $endpoint,
        private int $maximumFrameBytes,
        private int $uploadChunkBytes,
        private readonly int $maximumResultRows,
        private readonly int $maximumDownloadBytes,
        private readonly int $maximumUploadBytes,
        private readonly array $tlsInformation,
    ) {
    }

    public static function connect(
        string $host = '127.0.0.1',
        int $port = 2002,
        string $username = 'root',
        string $password = 'root',
        float $timeoutSeconds = 10.0,
        int $maximumFrameBytes = 8_388_608,
        int $uploadChunkBytes = 4_096,
        int $maximumResultRows = 100_000,
        int $maximumDownloadBytes = 67_108_864,
        ?TlsOptions $tlsOptions = null,
        int $maximumUploadBytes = 1_073_741_824,
    ): self {
        self::validateConnectionOptions(
            $host,
            $port,
            $username,
            $timeoutSeconds,
            $maximumFrameBytes,
            $uploadChunkBytes,
            $maximumResultRows,
            $maximumDownloadBytes,
            $maximumUploadBytes,
        );

        $tlsOptions ??= new TlsOptions();
        if (in_array('tls', $tlsOptions->connectionSchemes(), true) && !extension_loaded('openssl')) {
            throw new FoxyException('The OpenSSL extension is required for TLS.', 'TLS_CONFIG');
        }
        $stream = false;
        $endpoint = '';
        $tlsInformation = [];
        $errors = [];
        foreach ($tlsOptions->connectionSchemes() as $scheme) {
            $endpoint = self::buildEndpoint($host, $port, $scheme);
            $errorCode = 0;
            $errorMessage = '';
            $context = $scheme === 'tls'
                ? stream_context_create(['ssl' => $tlsOptions->contextOptions($host)])
                : stream_context_create();
            $stream = @stream_socket_client(
                $endpoint,
                $errorCode,
                $errorMessage,
                $timeoutSeconds,
                STREAM_CLIENT_CONNECT,
                $context,
            );
            if ($stream === false) {
                $errors[] = "{$scheme}: " . ($errorMessage === '' ? 'unknown socket error' : $errorMessage);
                continue;
            }
            try {
                $tlsInformation = $tlsOptions->validateSession($stream, $host, $port);
                break;
            } catch (FoxyException $exception) {
                fclose($stream);
                $stream = false;
                throw $exception;
            }
        }
        if ($stream === false) {
            throw new FoxyException(
                'Unable to connect to FoxyDB: ' . implode('; ', $errors),
                'CONNECTION_FAILED',
            );
        }

        if (!stream_set_blocking($stream, true)) {
            fclose($stream);
            throw new FoxyException('Unable to configure the FoxyDB connection.', 'CONNECTION_IO');
        }
        $seconds = (int) floor($timeoutSeconds);
        $microseconds = (int) round(($timeoutSeconds - $seconds) * 1_000_000);
        if ($microseconds === 1_000_000) {
            $seconds++;
            $microseconds = 0;
        }
        if (!stream_set_timeout($stream, $seconds, $microseconds)) {
            fclose($stream);
            throw new FoxyException('Unable to configure the FoxyDB timeout.', 'CONNECTION_IO');
        }

        $client = new self(
            $stream,
            $endpoint,
            $maximumFrameBytes,
            $uploadChunkBytes,
            $maximumResultRows,
            $maximumDownloadBytes,
            $maximumUploadBytes,
            $tlsInformation,
        );

        try {
            $hello = $client->read();
            if (($hello['type'] ?? null) !== 'hello'
                || ($hello['server'] ?? null) !== 'FoxyDB'
                || ($hello['protocol'] ?? null) !== self::PROTOCOL_VERSION) {
                throw new FoxyException('Server sent an invalid greeting.', 'PROTOCOL_ERROR');
            }
            $client->applyServerLimits($hello);
            $client->serverInfo = $hello;
            $client->validateHelloTls($hello);

            if (($hello['authenticated'] ?? false) !== true) {
                if (($hello['authentication'] ?? null) !== 'username_password') {
                    throw new FoxyException('Server requested an unsupported authentication method.', 'PROTOCOL_ERROR');
                }
                $response = $client->request([
                    'type' => 'auth',
                    'username' => $username,
                    'password' => $password,
                    'limits' => $client->clientLimits(),
                ]);
                $client->assertSuccess($response, 'auth');
                if (!is_string($response['username'] ?? null) || !is_string($response['database'] ?? null)) {
                    throw new FoxyException('Server sent an invalid authentication response.', 'PROTOCOL_ERROR');
                }
                $client->authenticatedUsername = $response['username'];
                $client->currentDatabase = $response['database'];
            } else {
                $client->authenticatedUsername = $username;
                $database = $hello['database'] ?? null;
                $client->currentDatabase = is_string($database) ? $database : null;
            }

            $tlsOptions->persistSession($tlsInformation);
            return $client;
        } catch (\Throwable $exception) {
            $client->close();
            throw $exception;
        }
    }

    public function query(string $sql, array $parameters = []): QueryResult
    {
        if (trim($sql) === '') {
            throw new FoxyException('SQL statement cannot be empty.', 'INVALID_VALUE');
        }

        try {
            $result = $this->executeQuery($sql, $parameters);
            $database = $result->metadata['database'] ?? null;
            if ($result->kind === 'command' && is_string($database) && $this->startsWithKeyword($sql, 'USE')) {
                $this->currentDatabase = $database;
            }
            return $result;
        } catch (FoxyException $exception) {
            if ($this->isFatalConnectionError($exception)) {
                $this->close();
            }
            throw $exception;
        }
    }

    public function selectDatabase(string $database): QueryResult
    {
        if ($database === '' || str_contains($database, "\0")) {
            throw new FoxyException('Database name is invalid.', 'INVALID_VALUE');
        }

        $quoted = '`' . str_replace('`', '``', $database) . '`';
        $result = $this->query("USE {$quoted}");
        $selected = $result->metadata['database'] ?? null;
        $this->currentDatabase = is_string($selected) ? $selected : $database;

        return $result;
    }

    public function uploadFile(string $path, string $format = 'binary', ?string $transferId = null): array
    {
        if (!is_file($path) || !in_array($format, ['binary', 'utf8'], true)) {
            throw new FoxyException('Upload path or format is invalid.', 'INVALID_VALUE');
        }
        if ($transferId !== null && !$this->isValidTransferId($transferId)) {
            throw new FoxyException('Transfer identifier is invalid.', 'INVALID_VALUE');
        }

        $file = @fopen($path, 'rb');
        if ($file === false) {
            throw new FoxyException('Unable to open upload file.', 'STORAGE_IO');
        }
        $statistics = fstat($file);
        $bytes = $statistics['size'] ?? null;
        if (!is_int($bytes) || $bytes < 0 || $bytes > $this->maximumUploadBytes) {
            fclose($file);
            throw new FoxyException('Upload exceeds the client upload limit.', 'RESOURCE_LIMIT');
        }

        $transferId ??= bin2hex(random_bytes(12));
        $started = false;
        try {
            $response = $this->request([
                'type' => 'chunk_start',
                'transfer_id' => $transferId,
                'format' => $format,
                'bytes' => $bytes,
            ]);
            $this->assertSuccess($response, 'chunk_start');
            $started = true;

            $serverChunkBytes = $response['chunk_bytes'] ?? null;
            if (!is_int($serverChunkBytes) || $serverChunkBytes < 1
                || $serverChunkBytes > $this->maximumFrameBytes) {
                throw new FoxyException('Server sent an invalid upload chunk limit.', 'PROTOCOL_ERROR');
            }
            $frameBudget = max(1, $this->maximumFrameBytes - 1_024);
            $maximumRawFrameBytes = $frameBudget;
            $chunkBytes = min($this->uploadChunkBytes, $maximumRawFrameBytes, $serverChunkBytes);
            while (!feof($file)) {
                $data = fread($file, $chunkBytes);
                if ($data === false) {
                    throw new FoxyException('Unable to read upload file.', 'STORAGE_IO');
                }
                if ($data === '') {
                    break;
                }
                $this->sendUploadData($transferId, $data, $chunkBytes);
            }

            $response = $this->request(['type' => 'chunk_end', 'transfer_id' => $transferId]);
            $this->assertSuccess($response, 'chunk_end');
            $started = false;
        } catch (\Throwable $exception) {
            if ($started && $this->isConnected()) {
                try {
                    $this->request(['type' => 'chunk_abort', 'transfer_id' => $transferId]);
                } catch (\Throwable) {
                }
            }
            if ($exception instanceof FoxyException && $this->isFatalConnectionError($exception)) {
                $this->close();
            }
            throw $exception;
        } finally {
            fclose($file);
        }

        return ['$transfer' => $transferId];
    }

    public function ping(): bool
    {
        try {
            $response = $this->request(['type' => 'ping']);
            $this->assertSuccess($response, 'pong');
            return true;
        } catch (FoxyException $exception) {
            if ($this->isFatalConnectionError($exception)) {
                $this->close();
            }
            throw $exception;
        }
    }

    public function isConnected(): bool
    {
        return is_resource($this->stream);
    }

    public function endpoint(): string
    {
        return $this->endpoint;
    }

    public function username(): ?string
    {
        return $this->authenticatedUsername;
    }

    public function database(): ?string
    {
        return $this->currentDatabase;
    }

    public function serverInfo(): array
    {
        return $this->serverInfo;
    }

    public function tlsInfo(): array
    {
        return $this->tlsInformation;
    }

    public function close(): void
    {
        if (is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }

    public function __destruct()
    {
        $this->close();
    }

    private function executeQuery(string $sql, array $parameters): QueryResult
    {
        foreach ($parameters as $key => $value) {
            $parameters[$key] = $this->encodeParameter($value);
        }

        $id = $this->allocateRequestId();
        $this->write(['type' => 'query', 'id' => $id, 'sql' => $sql, 'params' => $parameters]);
        $response = $this->readForRequest($id);
        if (($response['type'] ?? null) === 'error') {
            $this->throwResponseError($response);
        }

        if (($response['type'] ?? null) === 'result') {
            return $this->commandResult($response);
        }
        if (($response['type'] ?? null) !== 'result_start'
            || ($response['ok'] ?? false) !== true
            || ($response['kind'] ?? null) !== 'rows'
            || !is_array($response['columns'] ?? null)
            || !array_is_list($response['columns'])) {
            throw new FoxyException('Server sent an invalid query response.', 'PROTOCOL_ERROR');
        }
        foreach ($response['columns'] as $column) {
            if (!is_string($column)) {
                throw new FoxyException('Server sent an invalid result column.', 'PROTOCOL_ERROR');
            }
        }

        $rows = [];
        $downloads = [];
        $referencedDownloads = [];
        $downloadedBytes = 0;
        while (true) {
            $frame = $this->readForRequest($id);
            $type = $frame['type'] ?? null;
            if ($type === 'row') {
                if (!is_array($frame['row'] ?? null)) {
                    throw new FoxyException('Server sent an invalid row.', 'PROTOCOL_ERROR');
                }
                if (count($rows) >= $this->maximumResultRows) {
                    throw new FoxyException('Result exceeds the client row limit.', 'RESOURCE_LIMIT');
                }
                $rowBytes = FrameCodec::encodedValueBytes($frame['row'], $this->maximumFrameBytes);
                $downloadedBytes = $this->addDownloadBytes($downloadedBytes, $rowBytes);

                foreach ($frame['row'] as $value) {
                    if (!is_array($value) || !isset($value['$chunk'])) {
                        continue;
                    }
                    $transferId = $value['$chunk'];
                    $format = $value['format'] ?? null;
                    $bytes = $value['bytes'] ?? null;
                    if (!is_string($transferId) || !$this->isValidTransferId($transferId)
                        || !in_array($format, ['binary', 'utf8'], true)
                        || !is_int($bytes) || $bytes < 0 || isset($referencedDownloads[$transferId])) {
                        throw new FoxyException('Row contains an invalid chunk reference.', 'PROTOCOL_ERROR');
                    }
                    $downloadedBytes = $this->addDownloadBytes($downloadedBytes, $bytes);
                    $referencedDownloads[$transferId] = ['format' => $format, 'bytes' => $bytes];
                }
                $rows[] = $frame['row'];
                continue;
            }

            if ($type === 'chunk_start') {
                $transferId = $this->downloadId($frame);
                $format = $frame['format'] ?? null;
                $bytes = $frame['bytes'] ?? null;
                $direction = $frame['direction'] ?? null;
                if (!in_array($format, ['binary', 'utf8'], true) || !is_int($bytes) || $bytes < 0
                    || $direction !== 'download' || !isset($referencedDownloads[$transferId])
                    || isset($downloads[$transferId])
                    || $referencedDownloads[$transferId] !== ['format' => $format, 'bytes' => $bytes]) {
                    throw new FoxyException('Server sent an invalid download declaration.', 'PROTOCOL_ERROR');
                }
                $downloads[$transferId] = [
                    'format' => $format,
                    'bytes' => $bytes,
                    'stream' => $this->temporaryDownloadStream(),
                    'received' => 0,
                    'value' => null,
                    'state' => 'started',
                ];
                continue;
            }

            if ($type === 'chunk_data') {
                $transferId = $this->downloadId($frame);
                if (!isset($downloads[$transferId]) || $downloads[$transferId]['state'] !== 'started'
                    || !(($frame['data'] ?? null) instanceof BinaryValue)) {
                    throw new FoxyException('Server sent chunk data for an unknown download.', 'PROTOCOL_ERROR');
                }
                $data = $frame['data']->bytes;
                if ($data === '') {
                    throw new FoxyException('Server sent an empty chunk data frame.', 'PROTOCOL_ERROR');
                }
                $received = $downloads[$transferId]['received'] + strlen($data);
                if ($received > $downloads[$transferId]['bytes']) {
                    throw new FoxyException('Download exceeded its declared length.', 'PROTOCOL_ERROR');
                }
                $this->writeTemporaryDownload($downloads[$transferId]['stream'], $data);
                $downloads[$transferId]['received'] = $received;
                continue;
            }

            if ($type === 'chunk_end') {
                $transferId = $this->downloadId($frame);
                if (!isset($downloads[$transferId]) || $downloads[$transferId]['state'] !== 'started'
                    || $downloads[$transferId]['received'] !== $downloads[$transferId]['bytes']
                    || ($frame['bytes'] ?? null) !== $downloads[$transferId]['bytes']) {
                    throw new FoxyException('Download length does not match its declaration.', 'PROTOCOL_ERROR');
                }
                $stream = $downloads[$transferId]['stream'];
                if (!rewind($stream)) {
                    throw new FoxyException('Unable to rewind a downloaded value.', 'CONNECTION_IO');
                }
                $value = stream_get_contents($stream);
                fclose($stream);
                unset($downloads[$transferId]['stream']);
                if (!is_string($value) || strlen($value) !== $downloads[$transferId]['bytes']) {
                    throw new FoxyException('Unable to materialize a downloaded value.', 'CONNECTION_IO');
                }
                if ($downloads[$transferId]['format'] === 'utf8' && preg_match('//u', $value) !== 1) {
                    throw new FoxyException('Downloaded text is not valid UTF-8.', 'PROTOCOL_ERROR');
                }
                $downloads[$transferId]['value'] = $value;
                $downloads[$transferId]['state'] = 'ended';
                continue;
            }

            if ($type === 'result_end') {
                if (($frame['ok'] ?? false) !== true) {
                    $this->throwResponseError($frame);
                }
                if (($frame['row_count'] ?? null) !== count($rows)) {
                    throw new FoxyException('Server result row count does not match the received rows.', 'PROTOCOL_ERROR');
                }
                foreach ($referencedDownloads as $transferId => $_declaration) {
                    if (($downloads[$transferId]['state'] ?? null) !== 'ended') {
                        throw new FoxyException('Result ended before all downloads completed.', 'PROTOCOL_ERROR');
                    }
                }
                break;
            }
            if ($type === 'error') {
                $this->throwResponseError($frame);
            }
            throw new FoxyException('Server sent an unexpected result frame.', 'PROTOCOL_ERROR');
        }

        foreach ($rows as &$row) {
            foreach ($row as &$value) {
                $value = $this->decodeValue($value, $downloads);
            }
            unset($value);
        }
        unset($row);

        return QueryResult::rows(
            $response['columns'],
            $rows,
            is_array($response['metadata'] ?? null) ? $response['metadata'] : [],
        );
    }

    private function commandResult(array $response): QueryResult
    {
        $affectedRows = $response['affected_rows'] ?? null;
        $lastInsertId = $response['last_insert_id'] ?? null;
        if (($response['ok'] ?? false) !== true || ($response['kind'] ?? null) !== 'command'
            || !is_int($affectedRows) || $affectedRows < 0
            || (!is_int($lastInsertId) && !is_string($lastInsertId) && $lastInsertId !== null)) {
            throw new FoxyException('Server sent an invalid command result.', 'PROTOCOL_ERROR');
        }

        return QueryResult::command(
            $affectedRows,
            $lastInsertId,
            is_array($response['metadata'] ?? null) ? $response['metadata'] : [],
        );
    }

    private function request(array $payload): array
    {
        $id = $this->allocateRequestId();
        $payload['id'] = $id;
        $this->write($payload);
        return $this->readForRequest($id);
    }

    private function readForRequest(int $id): array
    {
        $response = $this->read();
        if (($response['id'] ?? null) !== $id) {
            if (($response['type'] ?? null) === 'error' && ($response['id'] ?? null) === null) {
                $this->throwResponseError($response);
            }
            throw new FoxyException('Unexpected response identifier.', 'PROTOCOL_ERROR');
        }
        return $response;
    }

    private function assertSuccess(array $response, string $expectedType): void
    {
        if (($response['type'] ?? null) === 'error' || ($response['ok'] ?? false) !== true) {
            $this->throwResponseError($response);
        }
        if (($response['type'] ?? null) !== $expectedType) {
            throw new FoxyException('Server sent an unexpected response type.', 'PROTOCOL_ERROR');
        }
    }

    private function throwResponseError(array $response): never
    {
        $error = is_array($response['error'] ?? null) ? $response['error'] : [];
        $message = $error['message'] ?? 'FoxyDB request failed.';
        $code = $error['code'] ?? 'REMOTE_ERROR';
        throw new FoxyException(
            is_string($message) && $message !== '' ? $message : 'FoxyDB request failed.',
            is_string($code) && $code !== '' ? $code : 'REMOTE_ERROR',
            is_array($error['details'] ?? null) ? $error['details'] : [],
        );
    }

    private function decodeValue(mixed $value, array $downloads): mixed
    {
        if ($value instanceof BinaryValue) {
            return $value;
        }
        if (!is_array($value)) {
            return $value;
        }
        if (isset($value['$chunk']) && is_string($value['$chunk'])) {
            $transferId = $value['$chunk'];
            if (!isset($downloads[$transferId]) || !is_string($downloads[$transferId]['value'])) {
                throw new FoxyException('A result references a missing download.', 'PROTOCOL_ERROR');
            }
            return $downloads[$transferId]['format'] === 'binary'
                ? new BinaryValue($downloads[$transferId]['value'])
                : $downloads[$transferId]['value'];
        }

        return $value;
    }

    private function encodeParameter(mixed $value): mixed
    {
        if ($value instanceof BinaryValue) {
            return $value;
        }
        if (is_object($value) || is_resource($value)) {
            throw new FoxyException('Unsupported client parameter value.', 'INVALID_VALUE');
        }

        return $value;
    }

    private function downloadId(array $frame): string
    {
        $transferId = $frame['transfer_id'] ?? null;
        if (!is_string($transferId) || !$this->isValidTransferId($transferId)) {
            throw new FoxyException('Server sent an invalid transfer identifier.', 'PROTOCOL_ERROR');
        }

        return $transferId;
    }

    private function addDownloadBytes(int $current, int $bytes): int
    {
        if ($bytes > $this->maximumDownloadBytes - $current) {
            throw new FoxyException('Result exceeds the client download limit.', 'RESOURCE_LIMIT');
        }

        return $current + $bytes;
    }

    private function temporaryDownloadStream()
    {
        $stream = @fopen('php://temp/maxmemory:1048576', 'w+b');
        if ($stream === false) {
            throw new FoxyException('Unable to allocate a temporary download stream.', 'RESOURCE_LIMIT');
        }

        return $stream;
    }

    private function writeTemporaryDownload($stream, string $data): void
    {
        $offset = 0;
        $length = strlen($data);
        while ($offset < $length) {
            $written = @fwrite($stream, substr($data, $offset));
            if ($written === false || $written === 0) {
                throw new FoxyException('Unable to buffer a downloaded value.', 'RESOURCE_LIMIT');
            }
            $offset += $written;
        }
    }

    private function sendUploadData(string $transferId, string $data, int &$chunkBytes): void
    {
        $offset = 0;
        $length = strlen($data);
        while ($offset < $length) {
            $part = substr($data, $offset, min($chunkBytes, $length - $offset));
            try {
                $response = $this->request([
                    'type' => 'chunk_data',
                    'transfer_id' => $transferId,
                    'data' => new BinaryValue($part),
                ]);
                $this->assertSuccess($response, 'chunk_data');
                $offset += strlen($part);
            } catch (FoxyException $exception) {
                if ($exception->errorCode !== 'PROTOCOL_ERROR'
                    || $exception->getMessage() !== 'Chunk data is invalid or too large.'
                    || $chunkBytes === 1) {
                    throw $exception;
                }
                $chunkBytes = max(1, intdiv($chunkBytes, 2));
            }
        }
    }

    private function allocateRequestId(): int
    {
        $id = $this->nextRequestId;
        $this->nextRequestId = $id === PHP_INT_MAX ? 1 : $id + 1;
        return $id;
    }

    private function write(array $payload): void
    {
        if (!is_resource($this->stream)) {
            throw new FoxyException('Client is not connected.', 'CONNECTION_CLOSED');
        }
        try {
            FrameCodec::write($this->stream, $payload, $this->maximumFrameBytes);
        } catch (FoxyException $exception) {
            if (in_array($exception->errorCode, ['PROTOCOL_ERROR', 'FRAME_TOO_LARGE'], true)) {
                throw new FoxyException(
                    'Unable to encode FoxyDB request: ' . $exception->getMessage(),
                    'INVALID_VALUE',
                    [],
                    $exception,
                );
            }
            throw $exception;
        }
    }

    private function read(): array
    {
        if (!is_resource($this->stream)) {
            throw new FoxyException('Client is not connected.', 'CONNECTION_CLOSED');
        }
        $payload = FrameCodec::read($this->stream, $this->maximumFrameBytes);
        if (array_key_exists('limits', $payload)) {
            $this->applyServerLimits($payload);
        }
        return $payload;
    }

    private function isFatalConnectionError(FoxyException $exception): bool
    {
        return in_array($exception->errorCode, [
            'PROTOCOL_ERROR',
            'RESOURCE_LIMIT',
            'CONNECTION_CLOSED',
            'CONNECTION_IO',
            'CONNECTION_TIMEOUT',
            'FRAME_TOO_LARGE',
        ], true);
    }

    private function isValidTransferId(string $transferId): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{1,128}$/', $transferId) === 1;
    }

    private function startsWithKeyword(string $sql, string $keyword): bool
    {
        $offset = 0;
        $length = strlen($sql);
        while ($offset < $length) {
            while ($offset < $length && ctype_space($sql[$offset])) {
                $offset++;
            }
            if (substr($sql, $offset, 2) === '--') {
                $newline = strpos($sql, "\n", $offset + 2);
                $offset = $newline === false ? $length : $newline + 1;
                continue;
            }
            if (($sql[$offset] ?? '') === '#') {
                $newline = strpos($sql, "\n", $offset + 1);
                $offset = $newline === false ? $length : $newline + 1;
                continue;
            }
            if (substr($sql, $offset, 2) === '/*') {
                $end = strpos($sql, '*/', $offset + 2);
                if ($end === false) {
                    return false;
                }
                $offset = $end + 2;
                continue;
            }
            break;
        }

        $candidate = substr($sql, $offset, strlen($keyword));
        $next = $sql[$offset + strlen($keyword)] ?? '';
        $nextPair = substr($sql, $offset + strlen($keyword), 2);
        return strcasecmp($candidate, $keyword) === 0
            && ($next === '' || ctype_space($next) || $next === '`' || $next === '"' || $next === '#'
                || $nextPair === '/*' || $nextPair === '--');
    }

    private function validateHelloTls(array $hello): void
    {
        $tls = $hello['tls'] ?? null;
        if ($this->tlsInformation === []) {
            if (is_array($tls) && ($tls['required'] ?? false) === true) {
                throw new FoxyException('Server requires a TLS connection.', 'TLS_REQUIRED');
            }
            return;
        }
        if (!is_array($tls) || ($tls['required'] ?? false) !== true) {
            throw new FoxyException('Server sent invalid TLS greeting metadata.', 'PROTOCOL_ERROR');
        }
        $advertised = $tls['certificate_sha256'] ?? null;
        $negotiated = $this->tlsInformation['certificate_sha256'] ?? null;
        if (!is_string($advertised) || !is_string($negotiated)
            || !hash_equals(strtolower($negotiated), strtolower($advertised))) {
            throw new FoxyException('TLS certificate does not match the server greeting.', 'TLS_HANDSHAKE');
        }
    }

    private function applyServerLimits(array $hello): void
    {
        $limits = $hello['limits'] ?? null;
        $frameBytes = is_array($limits) ? ($limits['frame_payload_bytes'] ?? null) : null;
        $chunkBytes = is_array($limits) ? ($limits['chunk_payload_bytes'] ?? null) : null;
        if (!is_array($limits) || array_is_list($limits)
            || !is_int($frameBytes) || $frameBytes < 1_024 || $frameBytes > FrameCodec::MAXIMUM_FRAME_BYTES
            || !is_int($chunkBytes) || $chunkBytes < 1 || $chunkBytes > $frameBytes) {
            throw new FoxyException('Server sent invalid protocol limit metadata.', 'PROTOCOL_ERROR');
        }

        $this->maximumFrameBytes = min($this->maximumFrameBytes, $frameBytes);
        $this->uploadChunkBytes = min($this->uploadChunkBytes, $chunkBytes);
    }

    private function clientLimits(): array
    {
        return [
            'frame_payload_bytes' => $this->maximumFrameBytes,
            'chunk_payload_bytes' => max(1, $this->maximumFrameBytes - 1_024),
        ];
    }

    private static function validateConnectionOptions(
        string $host,
        int $port,
        string $username,
        float $timeoutSeconds,
        int $maximumFrameBytes,
        int $uploadChunkBytes,
        int $maximumResultRows,
        int $maximumDownloadBytes,
        int $maximumUploadBytes,
    ): void {
        if ($host === '' || str_contains($host, '://') || preg_match('/[\x00-\x20\/\\\\]/', $host) === 1
            || $port < 1 || $port > 65_535 || $username === ''
            || !is_finite($timeoutSeconds) || $timeoutSeconds <= 0
            || $maximumFrameBytes < 1_024 || $maximumFrameBytes > FrameCodec::MAXIMUM_FRAME_BYTES
            || $uploadChunkBytes < 1
            || $maximumResultRows < 1 || $maximumDownloadBytes < 1 || $maximumUploadBytes < 0) {
            throw new FoxyException('Invalid client connection or resource limits.', 'INVALID_CONFIG');
        }
    }

    private static function buildEndpoint(string $host, int $port, string $scheme): string
    {
        if (str_starts_with($host, '[') || str_ends_with($host, ']')) {
            if (!str_starts_with($host, '[') || !str_ends_with($host, ']')) {
                throw new FoxyException('Invalid bracketed host.', 'INVALID_CONFIG');
            }
            $host = substr($host, 1, -1);
        }
        if ($host === '') {
            throw new FoxyException('Host cannot be empty.', 'INVALID_CONFIG');
        }

        $addressHost = str_contains($host, ':') ? "[{$host}]" : $host;
        return "{$scheme}://{$addressHost}:{$port}";
    }
}
