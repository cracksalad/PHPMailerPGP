<?php

namespace PHPMailer\PHPMailerPGP;

/**
 * @author  Travis Richardson (@ravisorg)
 * @author Andreas Wahlen
 * @license http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class PGPKeyManager
{
    use PGPHelper;

    /**
     * No error, key found and returned.
     */
    const LOOKUP_ERR_OK = 1;

    /**
     * Key not found.
     */
    const LOOKUP_ERR_NOT_FOUND = 2;

    /**
     * Rate limit of key server reached.
     */
    const LOOKUP_ERR_RATE_LIMIT = 3;

    /**
     * Key server is undergoing maintenance.
     */
    const LOOKUP_ERR_MAINTENANCE = 4;

    /**
     * Unknown error during lookup.
     */
    const LOOKUP_ERR_UNKNOWN = 255;


    /**
     * @var \Psr\Log\LoggerInterface|null
     */
    private $logger;

    /**
     * @param \Psr\Log\LoggerInterface|null $logger only the debug() method will be used
     */
    public function __construct($logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * Imports one or more keys into the local user's keychain. These can be secret or public keys,
     * generally anything exported by (eg) gpg --export. The results of the import are written to
     * the logger's debug log.
     * @param string $data One or more GPG/PGP keys
     * @throws PHPMailerPGPException
     * @return void
     * @see PGPKeyManager::importKeyFile()
     * @see PGPKeyManager::deleteKey()
     */
    public function importKey($data)
    {
        $this->initGNUPG();

        if (!file_exists($this->gnupgHome) || !is_writable($this->gnupgHome)) {
            throw new PHPMailerPGPException('GnuPG home directory is not writable, importing keys will fail');
        }

        /**
         * @psalm-var array{
         *      imported: int,
         *      unchanged: int,
         *      newuserids: int,
         *      newsubkeys: int,
         *      secretimported: int,
         *      secretunchanged: int,
         *      newsignatures: int,
         *      skippedkeys: int,
         *      fingerprint: string
         *  } $results
         */
        $results = $this->gnupg->import($data);
        if ($this->logger !== null) {
            $this->logger->debug(
                '{imported} keys imported, ' .
                '{unchanged} keys unchanged' .
                '{newuserids} new user ids imported' .
                '{newsubkeys} new subkeys imported' .
                '{secretimported} secret keys imported' .
                '{secretunchanged} secret keys unchanged' .
                '{newsignatures} new signatures imported' .
                '{skippedkeys} skipped keys',
                $results
            );
        }
    }

    /**
     * Imports one or more keys from a file into the local user's keychain. These can be secret or
     * public keys, generally anything exported by (eg) gpg --export. The results of the import are
     * written to PHPMailer's debug log.
     * @param string $path Path to GPG/PGP keys
     * @throws PHPMailerPGPException
     * @return void
     * @see PGPKeyManager::importKey()
     * @see PGPKeyManager::deleteKey()
     */
    public function importKeyFile($path)
    {
        if (!file_exists($path)) {
            throw new PHPMailerPGPException('Specified key file path does not exist');
        }
        $key = file_get_contents($path);
        if ($key === false) {
            throw new PHPMailerPGPException('Could not read key file');
        }
        $this->importKey($key);
    }

    /**
     * HKP based lookup on a key server.
     * @param string $query the e-mail address, hexadecimal key ID or a hexadecimal key fingerprint
     * @param string $keyserver FQDN of a key server
     * @param int $errCode will be set to one of the self::LOOKUP_ERR_* constants
     * @throws PHPMailerPGPException if request to key server fails
     * @return string|null the public key given by the key server or null if an error occurred
     *  (e.g. if key was not found)
     * @see PGPKeyManager::importKey()
     */
    public function lookupKeyServer($query, $keyserver = 'keys.openpgp.org', &$errCode = 0)
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'ignore_errors' => true
            ]
        ]);
        $stream = fopen(
            'https://' . $keyserver . '/pks/lookup?op=get&options=mr&search=' . $query,
            'r',
            false,
            $context
        );
        if ($stream === false) {
            throw new PHPMailerPGPException('Unable to send request to key server');
        }

        /**
         * @psalm-var array{
         *    timed_out: bool,
         *    blocked: bool,
         *    eof: bool,
         *    unread_bytes: int,
         *    stream_type: string,
         *    wrapper_type: string,
         *    wrapper_data: list<string>,
         *    mode: string,
         *    seekable: bool,
         *    uri: string,
         *    crypto: array
         *  } $meta
         */
        $meta = stream_get_meta_data($stream);
        $res = stream_get_contents($stream);
        fclose($stream);

        if ($res !== false) {
            // find last HTTP status line index (when redirects occur, there might be multiple HTTP status lines)
            $httpStatusIndex = 0;
            foreach ($meta['wrapper_data'] as $index => $item) {
                if (strpos($item, 'HTTP/') === 0) {
                    $httpStatusIndex = $index;
                }
            }

            $parts = explode(' ', $meta['wrapper_data'][$httpStatusIndex], 3);
            switch ($parts[1]) {
                case 200:       // OK
                    $errCode = self::LOOKUP_ERR_OK;
                    return $res;
                case 404:       // Not Found
                    $errCode = self::LOOKUP_ERR_NOT_FOUND;
                    break;
                case 429:       // Too Many Requests
                    $errCode = self::LOOKUP_ERR_RATE_LIMIT;
                    break;
                case 503:       // Service Unavailable
                    $errCode = self::LOOKUP_ERR_MAINTENANCE;
                    break;
                default:
                    $errCode = self::LOOKUP_ERR_UNKNOWN;
            }
        } else {
            $errCode = self::LOOKUP_ERR_UNKNOWN;
        }
        return null;
    }

    /**
     * Delete a previously imported key.
     * @param string $key the e-mail address, hexadecimal key ID or a hexadecimal key fingerprint
     * @param bool $deletePrivateKey wether to delete corresponding private keys as well
     * @return void
     * @see PGPKeyManager::importKey()
     */
    public function deleteKey($key, $deletePrivateKey)
    {
        $this->initGNUPG();
        if (!file_exists($this->gnupgHome) || !is_writable($this->gnupgHome)) {
            throw new PHPMailerPGPException('GnuPG home directory is not writable, deleting keys will fail');
        }

        /**
         * @var boolean $res
         */
        $res = $this->gnupg->deletekey($key, $deletePrivateKey);
        if ($this->logger !== null) {
            if ($res) {
                $this->logger->debug('successfully deleted key "{key}"', ['key' => $key]);
            } else {
                $this->logger->debug('failed to delete key "{key}"', ['key' => $key]);
            }
        }
    }

    /**
     * To check if an email can be send to some address in an encrypted fashion, use
     * `if(count($mailer->getKeys('my-address@example.com', 'encrypt')) === 1) sendEncrypted();`
     * Currently one can send encrypted mails only to addresses with exactly one known key.
     * Obviously you can not send to addresses without a key, but you can also not send to
     * addresses with several (known) keys.
     * @param string $identifier Any identifier that could be used to search for a key (usually an
     *  email address, but could be a key fingerprint, key ID, name, etc)
     * @param string $purpose The purpose the key will be used for (either 'sign' or 'encrypt').
     *  Used to ensure that the key being returned will be suitable for the intended purpose.
     * @return string[] The key fingerprints
     * @psalm-return list<string>
     */
    public function getKeys($identifier, $purpose)
    {
        $this->initGNUPG();
        /**
         * @psalm-var list<array{
         *    disabled: boolean,
         *    expired: boolean,
         *    revoked: boolean,
         *    is_secret: boolean,
         *    can_sign: boolean,
         *    can_encrypt: boolean,
         *    uids: list<array{
         *      name: string,
         *      comment: string,
         *      email: string,
         *      uid: string,
         *      revoked: bool,
         *      invalid: bool
         *    }>,
         *    subkeys: list<array{
         *      fingerprint: string,
         *      keyid: string,
         *      timestamp: int,
         *      expires: int,
         *      is_secret: bool,
         *      invalid: bool,
         *      can_encrypt: bool,
         *      can_sign: bool,
         *      disabled: bool,
         *      expired: bool,
         *      revoked: bool
         *    }>
         *  }> $keys
         */
        $keys = $this->gnupg->keyinfo($identifier);
        $fingerprints = [];
        foreach ($keys as $key) {
            if ($key['disabled'] || $key['expired'] || $key['revoked']) {
                continue;
            }
            if ($purpose === 'sign' && !$key['can_sign']) {
                continue;
            }
            if ($purpose === 'encrypt' && !$key['can_encrypt']) {
                continue;
            }
            foreach ($key['subkeys'] as $subkey) {
                if ($subkey['disabled'] || $subkey['expired'] || $subkey['revoked'] || $subkey['invalid']) {
                    continue;
                }
                if ($purpose === 'sign' && !$subkey['can_sign']) {
                    continue;
                }
                if ($purpose === 'encrypt' && !$subkey['can_encrypt']) {
                    continue;
                }
                $fingerprints[] = $subkey['fingerprint'];
            }
        }
        return $fingerprints;
    }
}
