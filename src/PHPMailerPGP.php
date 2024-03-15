<?php

namespace PHPMailer\PHPMailerPGP;

use PHPMailer\PHPMailer\PHPMailer;

/**
 * PHPMailerPGP - PHPMailer subclass adding PGP/MIME signing and encryption.
 * @author  Travis Richardson (@ravisorg)
 * @author  Andreas Wahlen
 * @license http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class PHPMailerPGP extends PHPMailer
{
    use PGPHelper;

    /**
     * Should the message be encrypted.
     * @var boolean
     * @see PHPMailerPGP::encrypt()
     */
    protected $encrypted = false;

    /**
     * Should the message be signed.
     * @var boolean
     * @see PHPMailerPGP::sign()
     */
    protected $signed = false;

    /**
     * Should the message use Memory Hole protected email headers. This will include versions of
     * the subject, to, from, and cc headers in the part of the message that is signed and/or
     * encrypted. For encrypted emails, the plaintext subject will be replaced with the words
     * "Encrypted Message". Note that you must have an email client that understands Memory Hole
     * headers in order to take advantage of this, and if you don't, you'll see "Encrypted Message"
     * as the subject of encrypted emails instead of the real subject. This has no effect if both
     * signing and encryption are disabled.
     * @var boolean
     * @see https://github.com/autocrypt/memoryhole
     */
    protected $protectedHeaders = false;

    /**
     * Stores the original (unencrypted) subject line.
     * @var string
     */
    protected $unprotectedSubject = '';

    /**
     * If encrypting the email, should the list of recipients from the email be used to try and
     * find encryption keys? ie: if you're sending an encrypted email, in theory you want a copy
     * that all of them can decrypt. This may, however, not be true if you're sending to an email
     * alias (and their public key is listed under a different address).
     * @var boolean
     * @see PHPMailerPGP::autoAddRecipients()
     */
    protected $autoRecipients = true;

    /**
     * If signing the email, should the signing key be selected based on the From address in the
     * email? Similar to $autoRecipients but for the signature.
     * @var boolean
     * @see PHPMailerPGP::autoAddSignature()
     */
    protected $autoSign = true;

    /**
     * An associative array of identifier=>keyFingerprint for the recipients we'll encrypt the email
     * to, where identifier is usually the email address, but could be anything used to look up a
     * key (including the fingerprint itself). This is populated either by autoAddRecipients or by
     * calling addRecipient.
     * @var array
     * @psalm-var array<string, string>
     * @see PHPMailerPGP::autoAddRecipients()
     * @see PHPMailerPGP::addRecipient()
     */
    protected $recipientKeys = [];

    /**
     * The fingerprint of the key that will be used to sign the email. Populated either with
     * autoAddSignature or addSignature.
     * @var string|null
     * @see PHPMailerPGP::autoAddSignature()
     * @see PHPMailerPGP::addSignature()
     */
    protected $signingKey = null;

    /**
     * An associative array of keyFingerprint=>passwords to decrypt secret keys (if needed).
     * Populated by calling addKeyPassphrase. Pointless at the moment because the GnuPG module in
     * PHP doesn't support decrypting keys with passwords. The command line client does, so this
     * method stays for now.
     * @var array
     * @psalm-var array<string, string>
     * @see PHPMailerPGP::addKeyPassphrase()
     */
    private $keyPassphrases = [];


    /**
     * The MIME boundary string for PGP related parts.
     *
     * @var string
     */
    protected $pgpBoundary = '';

    /**
     * Constructor.
     * @param boolean|null $exceptions Should we throw external exceptions?
     */
    public function __construct($exceptions = null)
    {
        // This is not a great way to do this (adding it to __construct) but there doesn't seem to
        // be a better way that can include the dynamic version number of PHPMailer...
        $this->XMailer = 'PHPMailerPGP (via PHPMailer ' . static::VERSION . ') .' .
            '(https://github.com/cracksalad/PHPMailerPGP)';

        parent::__construct($exceptions);
    }

    /**
     * Specify if you want the email to be signed or not. By default, emails are not signed, so you
     * must call this before calling Send() if you want a signature attached. If you choose to sign
     * and encrypt an email, it will always be signed first, then encrypted, regardless of the order
     * you call sign() and encrypt() in.
     *
     * Ideally this function would be called "sign", and be independet of what type of signatures
     * are being used, but because PHPMailer has a sign function that takes different parameters,
     * we can't do that without triggering notices.
     *
     * @param boolean $sign Sign the email? (true/false)
     * @return void
     * @see PHPMailerPGP::autoAddSignature()
     * @see PHPMailerPGP::addSignature()
     */
    public function pgpSign($sign = true)
    {
        $this->initGNUPG();
        $this->signed = (bool) $sign;
    }

    /**
     * If the email is being signed, should the signing key be looked up automatically based on the
     * From address in the email? This is on by default, if you turn it off you'll need to call
     * addSignature with the email address or fingerprint of the key you want to sign the message.
     *
     * Auto adding signatures will fail if the sender isn't found, or if multiple valid keys are
     * found for a sender. You can solve both issues by calling addSignature before sending.
     * @param boolean $autoAdd Automatically attempt to find signing keys based on From address?
     * @return void
     * @see PHPMailerPGP::addSignature()
     */
    public function autoAddSignature($autoAdd = true)
    {
        $this->initGNUPG();

        $this->autoSign = $autoAdd;
    }

    /**
     * Specifies the key to use when signing the message. To specify an exact key, pass in a key
     * fingerprint as the identifier.
     * @param string $identifier Something to search for unique to the key you want to use. Often
     *  an email address, but could be a key fingerprint, key ID, name, etc.
     * @param string $passphrase If the secret key is encrypted, this is the passphrase used to
     *  decrypt it.
     *
     *  Unfortunately not supported in PHP's GnuPG module, so at the moment does nothing (kept
     *  because the command line gpg program can use it).
     * @return void
     * @see PHPMailerPGP::autoAddSignature()
     * @see PHPMailerPGP::addKeyPassphrase()
     */
    public function addSignature($identifier, $passphrase = null)
    {
        $this->initGNUPG();

        $keyFingerprint = $this->getKey($identifier, 'sign');

        $this->signingKey = $keyFingerprint;
        if ($passphrase) {
            $this->addKeyPassphrase($keyFingerprint, $passphrase);
        }
    }

    /**
     * Specify if you want the email to be encrypted or not. By default, emails are not encrypted,
     * so you must call this before calling Send() if you want the message encrypted. If you choose
     * to sign and encrypt an email, it will always be signed first, then encrypted, regardless of
     * the order you call sign() and encrypt() in.
     * @param boolean $encrypt Encrypt the email? (true/false)
     * @return void
     * @see PHPMailerPGP::autoAddRecipients()
     * @see PHPMailerPGP::addRecipient()
     */
    public function encrypt($encrypt = true)
    {
        $this->initGNUPG();
        $this->encrypted = (bool) $encrypt;
    }

    /**
     * Specify if the message use Memory Hole protected email headers. This will include versions of
     * the subject, to, from, and cc headers in the part of the message that is signed and/or
     * encrypted. For encrypted emails, the plaintext subject will be replaced with the words
     * "Encrypted Message". Note that you must have an email client that understands Memory Hole
     * headers in order to take advantage of this, and if you don't, you'll see "Encrypted Message"
     * as the subject of encrypted emails instead of the real subject. This has no effect if both
     * signing and encryption are disabled.
     * @param boolean $protectHeaders Protect some of the headers in the email? (true/false)
     * @return void
     * @see https://github.com/autocrypt/memoryhole
     */
    public function protectHeaders($protectHeaders = true)
    {
        $this->initGNUPG();
        $this->protectedHeaders = (bool) $protectHeaders;
    }

    /**
     * If the email is being encrypted, should the list of recipient email addresses (to, cc, bcc,
     * etc) in the email be used to automatically try and find encryption keys in the local keyring
     * before sending? This is on by default, if you turn it off you'll need to call addRecipient
     * for anyone who you want to encrypt a copy of the email for.
     *
     * Auto adding recipients will fail if a recipient isn't found, or if multiple valid keys are
     * found for a recipient. You can solve both issues by calling addRecipient before sending (you
     * can use autoAddRecipients and addRecipient together).
     * @param boolean $autoAdd Automatically attempt to find encryption keys based on recipients?
     * @return void
     * @see PHPMailerPGP::addRecipient()
     */
    public function autoAddRecipients($autoAdd = true)
    {
        $this->initGNUPG();
        $this->autoRecipients = (bool) $autoAdd;
    }

    /**
     * Adds a recipient to encrypt a copy of the email for. If you exclude a key fingerprint, we
     * will try to find a matching key based on the identifier. However if no match is found, or
     * if multiple valid keys are found, this will fail. Specifying a key fingerprint avoids these
     * issues.
     * @param string $identifier Something to search for unique to the key you want to use. Often
     *  an email address, but could be a key fingerprint, key ID, name, etc.
     * @param string $keyFingerprint The exact key fingerprint to use with this recipient.
     * @return void
     * @see PHPMailerPGP::autoAddRecipients()
     */
    public function addRecipient($identifier, $keyFingerprint = null)
    {
        $this->initGNUPG();

        if (!$keyFingerprint) {
            $keyFingerprint = $this->getKey($identifier, 'encrypt');
        }

        $this->recipientKeys[$identifier] = $keyFingerprint;
    }

    /**
     * If you're using a key that's encrypted, call this to specify the password to decrypt the key
     * before attempting to use it.
     *
     * Unfortunately not supported in PHP's GnuPG module, so at the moment does nothing (kept
     * because the command line gpg program can use it).
     * @param string $identifier Something to search for unique to the key you want to use. Often
     *  an email address, but could be a key fingerprint, key ID, name, etc.
     * @param string $passphrase If the secret key is encrypted, this is the passphrase used to
     *  decrypt it.
     * @return void
     */
    public function addKeyPassphrase($identifier, $passphrase)
    {
        $this->initGNUPG();

        $keyFingerprint = $this->getKey($identifier, 'sign');
        $this->keyPassphrases[$keyFingerprint] = $passphrase;
    }

    /**
     * Get the message MIME type headers.
     *
     * Extended from PHPMailer to add support for encrypted and signed content type headers.
     * @return string
     */
    public function getMailMIME()
    {
        $result = '';
        switch ($this->message_type) {
            case 'signed':
                $result .= $this->headerLine('Content-Type', 'multipart/signed; micalg="pgp-sha256";');
                $result .= $this->textLine("\tprotocol=\"application/pgp-signature\";");
                $result .= $this->textLine("\tboundary=\"" . $this->pgpBoundary . '"');
                break;
            case 'encrypted':
                $result .= $this->headerLine('Content-Type', 'multipart/encrypted;');
                $result .= $this->textLine("\tprotocol=\"application/pgp-encrypted\";");
                $result .= $this->textLine("\tboundary=\"" . $this->pgpBoundary . '"');
                break;
            default:
                $result = parent::getMailMIME();
                break;
        }

        if ($this->Mailer != 'mail') {
            $result .= static::$LE;
        }

        return $result;
    }

    /**
     * Prepare a message for sending. Overridden here so we can replace the subject line with
     * something generic if protectedHeaders is enabled.
     * @return boolean
     */
    public function preSend()
    {
        // Remember what the original subject line was.
        $this->unprotectedSubject = $this->Subject;

        // Replace the container's subject line with something generic if this email is
        // being encrypted (otherwise there's no point).
        if ($this->protectedHeaders && $this->encrypted) {
            $this->Subject = 'Encrypted Message';
        }

        // Allow the regular preSend to run...
        $success = parent::preSend();

        // Now revert the subject back to the way it was
        if ($this->Subject === 'Encrypted Message') {
            $this->Subject = $this->unprotectedSubject;
        }

        return $success;
    }

    /**
     * Assemble the message body.
     *
     * Extended from PHPMailer to optionally sign and encrypt the message before it's sent.
     *
     * Returns an empty string on failure.
     * @throws PHPMailerPGPException
     * @return string The assembled message body
     */
    public function createBody()
    {
        if ($this->signed) {
            // PGP/Mime requires line endings that are CRLF (RFC3156 section 5)
            static::$LE = self::CRLF;

            // PGP/Mime requires 7 bit encoding (RFC3156 section 3, 5.1)
            // This also handles wrapping long lines so they don't get messed with
            $this->Encoding = self::ENCODING_QUOTED_PRINTABLE;
        }

        // Get the "normal" (unsigned / unencrypted) body from the parent class.
        $body = parent::createBody();

        // If the parent returned an empty body, or if encrypting and signing are both disabled,
        // then there's no need to encrypt / sign anything.
        if (!$body || (!$this->signed && !$this->encrypted)) {
            return $body;
        }

        // If we're protecting headers, we need to build a container to keep the protected headers
        // and everything else in.
        if ($this->protectedHeaders) {
            // Build a few containers here
            // - multipart/mixed with protected headers
            // - text/rfc822-headers with protected headers
            // - the normal body that would have been in an unprotected email
            // Then we'll sign and/or encrypt that as a single part

            $containerBoundary = 'hdr_' . $this->generateId();

            // We want to include these headers a couple times, so let's generate them just once
            $containerHeaders = '';
            $containerHeaders .= $this->addrAppend('From', [[trim($this->From), $this->FromName]]);
            if (count($this->to) > 0) {
                $containerHeaders .= $this->addrAppend('To', $this->to);
            } else {
                $containerHeaders .= $this->headerLine('To', 'undisclosed-recipients:;');
            }
            if (count($this->cc) > 0) {
                $containerHeaders .= $this->addrAppend('Cc', $this->cc);
            }
            $containerHeaders .= $this->headerLine(
                'Subject',
                $this->encodeHeader($this->secureHeader(trim($this->unprotectedSubject)))
            );
            // Ideally we'd have the Message-ID here too, but PHPMailer doesn't generate it until after
            // the body is generated, and if we do that now, it'll be moved to lastMessageID. In other
            // words, there's no way to know what the correct message ID will be at this point.

            // Build the actual container
            $container = '';
            $container .= $this->headerLine(
                'Content-Type',
                $this->encodeHeader(self::CONTENT_TYPE_MULTIPART_MIXED .
                        '; boundary="' . $containerBoundary . '";' . static::$LE .
                        "\t" . 'protected-headers="v1"')
            );

            // Add in the container headers
            $container .= $containerHeaders;

            // Line break
            $container .= static::$LE;

            // Multipart break
            $container .= $this->textLine('--' . $containerBoundary);

            // The content type of this part (protected headers)
            $container .= $this->headerLine(
                'Content-Type',
                $this->encodeHeader('text/rfc822-headers; protected-headers="v1"')
            );
            $container .= $this->headerLine('Content-Disposition', 'inline');

            // Line break
            $container .= static::$LE;

            // Add in the headers (again)
            $container .= $containerHeaders;

            // Line break
            $container .= static::$LE;

            // Multipart break
            $container .= $this->textLine('--' . $containerBoundary);

            // The content type of this part (whatever it was for the body before we started embedding
            // it).
            $container .= $this->getMailMIME();

            // Now finally the actual body of the email
            $container .= $body;

            // Close the container with the boundary
            $container .= static::$LE;
            $container .= static::$LE;
            $container .= $this->textLine('--' . $containerBoundary . '--');

            // Container is done! Use it as the body for any further signing / encrypting
            $body = $container;
        }

        // If we're using PGP to sign the message, do that before encrypting.
        if ($this->signed) {
            // Generate a new "body" that contains all the mime parts of the existing body, encrypt
            // it, then replace the body with the encrypted content. We don't need to include the
            // headers like we do when encrypting below, because they've already been included in
            // the container (above).
            $signedBody = '';

            // If the message is not using protected headers, then we need to include the headers
            // that say what kind of message it is, before we include the body.
            if (!$this->protectedHeaders) {
                $signedBody .= $this->getMailMIME();
            }

            $signedBody .= $body;

            // Remove trailing whitespace from all lines and convert all line endings to CRLF
            // (RFC3156 section 5.1)
            $lines = preg_split('/(\r\n|\r|\n)/', rtrim($signedBody));
            if ($lines === false) {
                throw new PHPMailerPGPException('Invalid signed body');
            }
            for ($i = 0; $i < count($lines); $i++) {
                $lines[$i] = rtrim($lines[$i]) . "\r\n";
            }

            // Remove excess trailing newlines (RFC3156 section 5.4)
            $signedBody = rtrim(implode('', $lines)) . "\r\n";

            // Who is signing it?
            if (!$this->signingKey && $this->autoSign) {
                $this->addSignature($this->getKey($this->From, 'sign'));
            }
            if (!$this->signingKey) {
                throw new PHPMailerPGPException('Signing has been enabled, but no signature has been added. ' .
                        'Use autoAddSignature() or addSignature()');
            }

            // Sign it
            $signature = $this->pgpSignString($signedBody, $this->signingKey);

            // The main email MIME type is no longer what the developer specified, it's now
            // multipart/signed
            $this->message_type = 'signed';

            // Generate new boundaries, and make sure they're not the same as the old ones
            $this->pgpBoundary = 'sign_' . $this->generateId();

            // The body of the email is pretty simple, so instead of modifying all the various
            // functions to support PGP/Mime, we'll just build it here
            $body = '';
            $body .= $this->textLine('This is an OpenPGP/MIME signed message (RFC 4880 and 3156)');
            $body .= static::$LE;
            $body .= $this->textLine('--' . $this->pgpBoundary);
            $body .= $signedBody; // will already have a CRLF at the end, don't add another one
            $body .= static::$LE;
            $body .= $this->textLine('--' . $this->pgpBoundary);
            $body .= $this->textLine('Content-Type: application/pgp-signature; name="signature.asc"');
            $body .= $this->textLine('Content-Description: OpenPGP digital signature');
            $body .= $this->textLine('Content-Disposition: attachment; filename="signature.asc"');
            $body .= static::$LE;
            $body .= $signature;
            $body .= static::$LE;
            $body .= static::$LE;
            $body .= $this->textLine('--' . $this->pgpBoundary . '--');
        }

        // If we're using PGP to encrypt the message, do that now.
        if ($this->encrypted) {
            // Generate a new "body" that contains all the mime parts of the existing body, encrypt
            // it, then replace the body with the encrypted content.
            // Note that this body may be inherited from the signing code above, which inherited it
            // from the parent object.
            $encryptedBody = '';

            // If the message was signed, or the message does not include protected headers, then
            // we need to include the headers with the appropriate content types before we include
            // the body.
            if (!$this->protectedHeaders || $this->signed) {
                $encryptedBody .= $this->getMailMIME();
            }

            $encryptedBody .= $body;

            // Who are we sending it to?
            if ($this->autoRecipients) {
                /**
                 * @psalm-var array<string, true> $recipients
                 */
                $recipients = $this->getAllRecipientAddresses();
                /**
                 * @var string $recipient
                 */
                foreach (array_keys($recipients) as $recipient) {
                    if (!isset($this->recipientKeys[$recipient])) {
                        $this->addRecipient($recipient);
                    }
                }
            }
            if (!$this->recipientKeys) {
                throw new PHPMailerPGPException('Encryption has been enabled, but no recipients have been added. ' .
                    'Use autoAddRecipients() or addRecipient()');
            }

            // Encrypt it for all those people
            /**
             * @psalm-var list<string> $fingerprints
             */
            $fingerprints = array_values($this->recipientKeys);
            $encryptedBody = $this->pgpEncryptString($encryptedBody, $fingerprints);

            // Replace the email the developer built with an encrypted version
            $this->message_type = 'encrypted';
            $this->Encoding = self::ENCODING_7BIT;

            // Generate new boundaries, and make sure they're not the same as the old ones
            $this->pgpBoundary = 'encr_' . $this->generateId();

            // The body of the email is pretty simple, so instead of modifying all the various
            // functions to support PGP/Mime, we'll just build it here
            $body = '';
            $body .= $this->textLine('This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)');
            $body .= static::$LE;
            $body .= $this->textLine('--' . $this->pgpBoundary);
            $body .= $this->textLine('Content-Type: application/pgp-encrypted');
            $body .= $this->textLine('Content-Description: PGP/MIME version identification');
            $body .= static::$LE;
            $body .= $this->textLine('Version: 1');
            $body .= static::$LE;
            $body .= $this->textLine('--' . $this->pgpBoundary);
            $body .= $this->textLine('Content-Type: application/octet-stream; name="encrypted.asc"');
            $body .= $this->textLine('Content-Description: OpenPGP encrypted message');
            $body .= $this->textLine('Content-Disposition: inline; filename="encrypted.asc"');
            $body .= static::$LE;
            $body .= $encryptedBody;
            $body .= static::$LE;
            $body .= static::$LE;
            $body .= $this->textLine('--' . $this->pgpBoundary . '--');
        }

        return $body;
    }

    /**
     * Internal method used to sign a string with a secret key.
     * @param string $plaintext The string to be signed.
     * @param string $keyFingerprint The fingerprint of the secret key to be used to sign the
     *  string.
     * @return string The resulting ASCII armored detached signature
     * @throws PHPMailerPGPException
     */
    protected function pgpSignString($plaintext, $keyFingerprint)
    {
        if (isset($this->keyPassphrases[$keyFingerprint]) && $this->keyPassphrases[$keyFingerprint]) {
            $passphrase = $this->keyPassphrases[$keyFingerprint];
            $this->edebug('Using passphrase for signing key ' . $keyFingerprint);
        } else {
            $passphrase = '';
            $this->edebug('No passphrase specified for signing key ' . $keyFingerprint);
        }

        $this->gnupg->clearsignkeys();
        $this->gnupg->addsignkey($keyFingerprint, $passphrase);
        $this->gnupg->setsignmode(\gnupg::SIG_MODE_DETACH);
        $this->gnupg->setarmor(1);

        /**
         * @var string|false $signed
         */
        $signed = $this->gnupg->sign($plaintext);
        if ($signed) {
            return $signed;
        }

        // We were unable to find a method to sign data
        throw new PHPMailerPGPException('Unable to sign message ' .
            '(perhaps the secret key is encrypted with a passphrase?)');
    }

    /**
     * Internal method used to encrypt a string with one or more recipient keys.
     * @param string $plaintext The string to encrypt
     * @param array $keyFingerprints An array of key fingerprints to use to encrypt the string.
     * @psalm-param array<array-key, string> $keyFingerprints
     * @return string An ASCII armored encrypted string.
     * @throws PHPMailerPGPException
     */
    protected function pgpEncryptString($plaintext, $keyFingerprints)
    {
        $this->gnupg->clearencryptkeys();
        foreach ($keyFingerprints as $keyFingerprint) {
            $this->gnupg->addencryptkey($keyFingerprint);
        }

        $this->gnupg->setarmor(1);

        /**
         * @var string|false $encrypted
         */
        $encrypted = $this->gnupg->encrypt($plaintext);
        if ($encrypted) {
            return $encrypted;
        }

        // We were unable to find a method to encrypt data
        throw new PHPMailerPGPException('Unable to encrypt message');
    }

    /**
     * Internal method used to find a valid key fingerprint based on an identifier of some sort.
     * @param string $identifier Any identifier that could be used to search for a key (usually an
     *  email address, but could be a key fingerprint, key ID, name, etc)
     * @param string $purpose The purpose the key will be used for (either 'sign' or 'encrypt').
     *  Used to ensure that the key being returned will be suitable for the intended purpose.
     * @return string The key fingerprint
     * @throws PHPMailerPGPException
     */
    protected function getKey($identifier, $purpose)
    {
        $manager = new PGPKeyManager(
            $this->Debugoutput instanceof \Psr\Log\LoggerInterface ? $this->Debugoutput : null
        );
        $fingerprints = $manager->getKeys($identifier, $purpose);
        if (count($fingerprints) === 1) {
            return $fingerprints[0];
        }
        if (count($fingerprints) > 1) {
            throw new PHPMailerPGPException('Found more than one active key for ' . $identifier .
                ', use addRecipient() or addSignature()');
        }
        throw new PHPMailerPGPException('Unable to find an active key to ' . $purpose . ' for ' . $identifier .
            ', try importing keys first');
    }
}
