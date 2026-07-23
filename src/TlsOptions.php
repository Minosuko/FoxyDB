<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;

final readonly class TlsOptions
{
    private const MODES = ['DISABLED', 'PREFERRED', 'REQUIRED', 'VERIFY_CA', 'VERIFY_IDENTITY'];
    private const VERSIONS = ['TLSv1.2', 'TLSv1.3'];

    public function __construct(
        public string $mode = 'REQUIRED',
        public ?string $caFile = null,
        public ?string $caPath = null,
        public ?string $certificateFile = null,
        public ?string $privateKeyFile = null,
        public ?string $cipherList = null,
        public ?string $crlFile = null,
        public ?string $crlPath = null,
        public string $fipsMode = 'OFF',
        public ?string $sessionDataFile = null,
        public bool $continueOnFailedSessionReuse = false,
        public ?string $tlsCipherSuites = null,
        public array $tlsVersions = ['TLSv1.2', 'TLSv1.3'],
    ) {
        if (!in_array(strtoupper($mode), self::MODES, true)) {
            throw new FoxyException("Unsupported SSL mode: {$mode}", 'TLS_CONFIG');
        }
        if (!in_array(strtoupper($fipsMode), ['OFF', 'ON', 'STRICT'], true)) {
            throw new FoxyException("Unsupported SSL FIPS mode: {$fipsMode}", 'TLS_CONFIG');
        }
        if ($tlsVersions === [] || array_diff($tlsVersions, self::VERSIONS) !== []) {
            throw new FoxyException('TLS versions must contain TLSv1.2 and/or TLSv1.3.', 'TLS_CONFIG');
        }
        foreach ([$caFile, $certificateFile, $privateKeyFile, $crlFile] as $file) {
            if ($file !== null && !is_file($file)) {
                throw new FoxyException("TLS file does not exist: {$file}", 'TLS_CONFIG');
            }
        }
        foreach ([$caPath, $crlPath] as $path) {
            if ($path !== null && !is_dir($path)) {
                throw new FoxyException("TLS directory does not exist: {$path}", 'TLS_CONFIG');
            }
        }
        if (($certificateFile === null) !== ($privateKeyFile === null)) {
            throw new FoxyException('TLS client certificate and key must be provided together.', 'TLS_CONFIG');
        }
        if ($crlFile !== null || $crlPath !== null) {
            throw new FoxyException('This PHP TLS backend cannot enforce CRL options.', 'TLS_CONFIG');
        }
        if (strtoupper($fipsMode) !== 'OFF') {
            throw new FoxyException('This PHP TLS backend cannot activate or verify FIPS mode.', 'TLS_CONFIG');
        }
        if ($sessionDataFile !== null && is_dir($sessionDataFile)) {
            throw new FoxyException('TLS session data path must be a file.', 'TLS_CONFIG');
        }
    }

    public static function fromArray(array $options): self
    {
        $versions = $options['tls-version'] ?? 'TLSv1.2,TLSv1.3';
        $versions = array_values(array_filter(array_map('trim', explode(',', (string) $versions))));
        return new self(
            mode: strtoupper((string) ($options['ssl-mode'] ?? 'REQUIRED')),
            caFile: self::nullable($options['ssl-ca'] ?? null),
            caPath: self::nullable($options['ssl-capath'] ?? null),
            certificateFile: self::nullable($options['ssl-cert'] ?? null),
            privateKeyFile: self::nullable($options['ssl-key'] ?? null),
            cipherList: self::nullable($options['ssl-cipher'] ?? null),
            crlFile: self::nullable($options['ssl-crl'] ?? null),
            crlPath: self::nullable($options['ssl-crlpath'] ?? null),
            fipsMode: strtoupper((string) ($options['ssl-fips-mode'] ?? 'OFF')),
            sessionDataFile: self::nullable($options['ssl-session-data'] ?? null),
            continueOnFailedSessionReuse: self::boolean(
                $options['ssl-session-data-continue-on-failed-reuse'] ?? false,
            ),
            tlsCipherSuites: self::nullable($options['tls-ciphersuites'] ?? null),
            tlsVersions: $versions,
        );
    }

    public function connectionSchemes(): array
    {
        if ($this->sessionDataFile !== null) {
            return ['tls'];
        }

        return match (strtoupper($this->mode)) {
            'DISABLED' => ['tcp'],
            'PREFERRED' => ['tls', 'tcp'],
            default => ['tls'],
        };
    }

    public function contextOptions(string $host): array
    {
        $mode = strtoupper($this->mode);
        $verifyPeer = in_array($mode, ['VERIFY_CA', 'VERIFY_IDENTITY'], true);
        $options = [
            'verify_peer' => $verifyPeer,
            'verify_peer_name' => $mode === 'VERIFY_IDENTITY',
            'allow_self_signed' => !$verifyPeer,
            'peer_name' => trim($host, '[]'),
            'SNI_enabled' => true,
            'disable_compression' => true,
            'capture_peer_cert' => true,
            'crypto_method' => $this->clientCryptoMethod(),
        ];
        if ($this->caFile !== null) {
            $options['cafile'] = $this->caFile;
        }
        if ($this->caPath !== null) {
            $options['capath'] = $this->caPath;
        }
        if ($this->certificateFile !== null) {
            $options['local_cert'] = $this->certificateFile;
            $options['local_pk'] = $this->privateKeyFile;
        }
        if ($this->cipherList !== null) {
            $options['ciphers'] = $this->cipherList;
        }
        if ($this->tlsCipherSuites !== null) {
            $options['ciphersuites'] = $this->tlsCipherSuites;
        }

        return $options;
    }

    public function validateSession($stream, string $host, int $port): array
    {
        $metadata = stream_get_meta_data($stream);
        $crypto = is_array($metadata['crypto'] ?? null) ? $metadata['crypto'] : [];
        if ($crypto === []) {
            if (!in_array(strtoupper($this->mode), ['DISABLED', 'PREFERRED'], true)) {
                throw new FoxyException('The connection did not negotiate TLS.', 'TLS_REQUIRED');
            }
            return [];
        }

        $parameters = stream_context_get_params($stream);
        $certificate = $parameters['options']['ssl']['peer_certificate'] ?? null;
        $fingerprint = $certificate === null ? false : openssl_x509_fingerprint($certificate, 'sha256');
        if (!is_string($fingerprint)) {
            throw new FoxyException('Unable to inspect the peer TLS certificate.', 'TLS_HANDSHAKE');
        }
        $session = [
            'format' => 1,
            'host' => $host,
            'port' => $port,
            'certificate_sha256' => strtolower($fingerprint),
            'protocol' => (string) ($crypto['protocol'] ?? ''),
            'cipher_name' => (string) ($crypto['cipher_name'] ?? ''),
            'cipher_bits' => (int) ($crypto['cipher_bits'] ?? 0),
        ];
        if (!in_array($session['protocol'], $this->tlsVersions, true)) {
            throw new FoxyException(
                "Negotiated TLS version {$session['protocol']} is outside the requested policy.",
                'TLS_VERSION_MISMATCH',
            );
        }
        if ($this->tlsCipherSuites !== null && $session['protocol'] === 'TLSv1.3') {
            $allowed = preg_split('/[:,]/', $this->tlsCipherSuites, -1, PREG_SPLIT_NO_EMPTY);
            $allowed = array_map('trim', $allowed === false ? [] : $allowed);
            if (!in_array($session['cipher_name'], $allowed, true)) {
                throw new FoxyException(
                    'Negotiated TLS 1.3 cipher suite is outside the requested policy.',
                    'TLS_CIPHER_MISMATCH',
                );
            }
        }
        if ($this->hasSessionData()) {
            $previous = $this->readSessionData();
            $samePeer = ($previous['host'] ?? null) === $host
                && ($previous['port'] ?? null) === $port
                && ($previous['certificate_sha256'] ?? null) === $session['certificate_sha256'];
            if (!$samePeer && !$this->continueOnFailedSessionReuse) {
                throw new FoxyException('TLS session peer data could not be safely reused.', 'TLS_SESSION_REUSE_FAILED');
            }
            $session['previous_peer_mismatch'] = !$samePeer;
        }

        return $session;
    }

    public function persistSession(array $session): void
    {
        if ($this->sessionDataFile === null) {
            return;
        }
        $directory = dirname($this->sessionDataFile);
        if (!is_dir($directory)) {
            throw new FoxyException('TLS session data directory does not exist.', 'TLS_CONFIG');
        }
        try {
            $json = json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        } catch (\JsonException $exception) {
            throw new FoxyException('Unable to encode TLS session data.', 'TLS_CONFIG', [], $exception);
        }
        $temporary = @tempnam($directory, '.foxydb-tls-');
        if ($temporary === false || @file_put_contents($temporary, $json, LOCK_EX) !== strlen($json)) {
            if (is_string($temporary)) {
                @unlink($temporary);
            }
            throw new FoxyException('Unable to write TLS session data.', 'TLS_CONFIG');
        }
        @chmod($temporary, 0600);
        $this->publishSessionData($temporary);
    }

    private function readSessionData(): array
    {
        $path = is_file((string) $this->sessionDataFile)
            ? (string) $this->sessionDataFile
            : $this->sessionBackupPath();
        $json = @file_get_contents($path);
        if ($json === false) {
            throw new FoxyException('Unable to read TLS session data.', 'TLS_CONFIG');
        }
        try {
            $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new FoxyException('TLS session data is invalid.', 'TLS_CONFIG', [], $exception);
        }
        if (!is_array($data)) {
            throw new FoxyException('TLS session data is invalid.', 'TLS_CONFIG');
        }

        return $data;
    }

    private function hasSessionData(): bool
    {
        return $this->sessionDataFile !== null
            && (is_file($this->sessionDataFile) || is_file($this->sessionBackupPath()));
    }

    private function publishSessionData(string $temporary): void
    {
        $target = (string) $this->sessionDataFile;
        if (PHP_OS_FAMILY !== 'Windows') {
            if (!@rename($temporary, $target)) {
                @unlink($temporary);
                throw new FoxyException('Unable to publish TLS session data.', 'TLS_CONFIG');
            }
            return;
        }

        $backup = $this->sessionBackupPath();
        if (is_file($target)) {
            if (is_file($backup) && !@unlink($backup)) {
                @unlink($temporary);
                throw new FoxyException('Unable to replace stale TLS session data.', 'TLS_CONFIG');
            }
            if (!@rename($target, $backup)) {
                @unlink($temporary);
                throw new FoxyException('Unable to preserve existing TLS session data.', 'TLS_CONFIG');
            }
        }
        if (!@rename($temporary, $target)) {
            @unlink($temporary);
            if (!is_file($target) && is_file($backup)) {
                @rename($backup, $target);
            }
            throw new FoxyException('Unable to publish TLS session data.', 'TLS_CONFIG');
        }
        if (is_file($backup)) {
            @unlink($backup);
        }
    }

    private function sessionBackupPath(): string
    {
        return (string) $this->sessionDataFile . '.previous';
    }

    private function clientCryptoMethod(): int
    {
        $method = 0;
        $constants = [
            'TLSv1.2' => 'STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT',
            'TLSv1.3' => 'STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT',
        ];
        foreach ($this->tlsVersions as $version) {
            if (defined($constants[$version])) {
                $method |= constant($constants[$version]);
            }
        }
        if ($method === 0) {
            throw new FoxyException('Requested TLS versions are unavailable in this PHP build.', 'TLS_CONFIG');
        }

        return $method;
    }

    private static function nullable(mixed $value): ?string
    {
        return $value === null || $value === '' ? null : (string) $value;
    }

    private static function boolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        $parsed = filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        if ($parsed === null) {
            throw new FoxyException('Invalid boolean TLS option.', 'TLS_CONFIG');
        }

        return $parsed;
    }
}
