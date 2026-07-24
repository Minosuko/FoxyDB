# FoxyDB PHP Library

This directory contains the reusable PHP connector for FoxyDB binary protocol version 2. It provides a MySQL-style connection and query API without depending on the command-line client or server source tree.

Applications that do not need a database daemon can instead use [FoxyDB-serverless](https://github.com/Minosuko/FoxyDB-serverless), which opens a local FoxyDB bundle directly in the PHP process.

## Requirements

- 64-bit PHP 8.2 or newer
- The PHP `json` and `openssl` extensions

## Installation

Install the package with Composer:

```console
composer require minosuko/foxydb
```

For a repository checkout without Composer, load `library/src/Autoloader.php`.

## Connect And Query

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use FoxyDB\Client;
use FoxyDB\TlsOptions;

$db = Client::connect(
    host: '127.0.0.1',
    port: 2002,
    username: 'root',
    password: 'root',
    tlsOptions: new TlsOptions(
        mode: 'VERIFY_IDENTITY',
        caFile: __DIR__ . '/server.crt',
    ),
);

$db->selectDatabase('application');

$insert = $db->query(
    'INSERT INTO users (email, enabled) VALUES (?, ?)',
    ['fox@example.test', true],
);
echo $insert->lastInsertId . PHP_EOL;

$result = $db->query('SELECT id, email FROM users WHERE enabled = ?', [true]);
foreach ($result as $row) {
    echo $row['email'] . PHP_EOL;
}

$db->close();
```

`query()` sends values separately from SQL. Use `?` placeholders rather than interpolating application values. A `QueryResult` exposes `kind`, `columns`, `rows`, `affectedRows`, `lastInsertId`, and `metadata`. Results are iterable and countable.

Connection helpers include `selectDatabase()`, `ping()`, `isConnected()`, `database()`, `username()`, `endpoint()`, `serverInfo()`, `tlsInfo()`, and `close()`.

## Binary Values

Use `BinaryValue` for an inline `BINARY` or `BLOB` parameter:

```php
use FoxyDB\Value\BinaryValue;

$db->query('INSERT INTO files (name, body) VALUES (?, ?)', [
    'small.bin',
    new BinaryValue($bytes),
]);
```

`BinaryValue` and uploaded chunks are transmitted as raw typed bytes. Protocol version 2 does not use JSON or Base64 for wire values. During the greeting, the library validates the server's advertised frame and chunk payload limits and applies the lower local or remote limit.

Use `uploadFile()` for large binary or UTF-8 values. The returned transfer reference is single-use:

```php
$body = $db->uploadFile(__DIR__ . '/archive.bin', 'binary');
$db->query('INSERT INTO files (name, body) VALUES (?, ?)', ['archive.bin', $body]);
```

TLS modes are `DISABLED`, `PREFERRED`, `REQUIRED`, `VERIFY_CA`, and `VERIFY_IDENTITY`. `REQUIRED` is the default; use `VERIFY_IDENTITY` with a trusted certificate for production connections.

## Tests

From this directory, run:

```console
php tests/run.php
```
