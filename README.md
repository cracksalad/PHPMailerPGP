# PHPMailerPGP - A full-featured email creation and transfer class for PHP with support for PGP/GPG email signing and encryption.


**THIS PROJECT HAS BEEN MOVED TO [https://github.com/cracksalad/PHPMailer-PGP](https://github.com/cracksalad/PHPMailer-PGP)!**

This repository is a fork of a fork of PHPMailer, which does not make sense any more. Additionally forks and especially forks of forks are unvisible in the GitHub search. 
That is why I have decided to move it. The packagist/composer package has not been moved and is the same as before, no changes necessary.


[![Latest Stable Version](http://poser.pugx.org/cracksalad/phpmailer-pgp/v)](https://packagist.org/packages/cracksalad/phpmailer-pgp)
[![Total Downloads](http://poser.pugx.org/cracksalad/phpmailer-pgp/downloads)](https://packagist.org/packages/cracksalad/phpmailer-pgp)
[![License](http://poser.pugx.org/cracksalad/phpmailer-pgp/license)](https://packagist.org/packages/cracksalad/phpmailer-pgp)
[![PHP Version Require](http://poser.pugx.org/cracksalad/phpmailer-pgp/require/php)](https://packagist.org/packages/cracksalad/phpmailer-pgp)
[![Psalm Type Coverage](https://shepherd.dev/github/cracksalad/PHPMailerPGP/coverage.svg)](https://packagist.org/packages/cracksalad/phpmailer-pgp)

This project is based on [ravisorg/PHPMailer](https://github.com/ravisorg/PHPMailer) and replaced PHPMailer inside the repository with PHPMailer as a dependency. It also adds Composer support and includes minor changes to the code itself.

See the main [PHPMailer](https://www.github.com/PHPMailer/PHPMailer) page for all the features PHPMailer supports. This page will document only the PGP additions.

## Class Features

- Uses the [PHP GnuPG extension](https://secure.php.net/manual/en/ref.gnupg.php) for encryption / signing
- Encrypt and/or sign outgoing emails with PGP to one or multiple recipients (signs first, then encrypts when both are enabled)
- Automatically selects the proper keys based on sender / recipients (or manually specify them)
- Use keys in the GPG keychain or from a specified file
- Supports file attachments (and encrypts/signs them)
- Builds PGP/MIME emails so that attachments are encrypted (and signed) as well as the email bodies
- Supports optional [Memory Hole protected email headers](https://github.com/autocrypt/memoryhole) (for verified/encrypted subjects, and verified from, to, and cc recipients)
- Uses standard PHPMailer functions so that, in theory, any email you can create with PHPMailer can be encrypted/signed with PHPMailerPGP
- Adheres to PHPMailer's coding standards
- (Mostly) built generically so that other encryption systems (S/MIME) could use the same syntax in their classes

## Why you might need it

In an ideal world, users would provide you with their PGP keys and you could use this to send secure emails to them. More realistically: because your server sends emails with lots of sensitive information in them, and you should be encrypting them.

## License

This software is distributed under the [LGPL 2.1](http://www.gnu.org/licenses/lgpl-2.1.html) license. Please read LICENSE for information on the software availability and distribution.

## Installation

Add this package to your composer.json like this:

```bash
composer require cracksalad/phpmailer-pgp
```

### Dependencies

* gnupg/gnupg2
* [PHP's PECL extension for gnupg](https://pecl.php.net/package/gnupg)
* PHP 5.5+

## A Simple Example

Set up your PHPMailer like you would normally:

```php
<?php
require_once 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailerPGP;

$mailer = new PHPMailerPGP();

//$mailer->SMTPDebug = 3;                               // Enable verbose debug output

$mailer->isSMTP();                                      // Set mailer to use SMTP
$mailer->Host = 'smtp1.example.com;smtp2.example.com';  // Specify main and backup SMTP servers
$mailer->SMTPAuth = true;                               // Enable SMTP authentication
$mailer->Username = 'user@example.com';                 // SMTP username
$mailer->Password = 'secret';                           // SMTP password
$mailer->SMTPSecure = 'tls';                            // Enable TLS encryption, `ssl` also accepted
$mailer->Port = 587;                                    // TCP port to connect to

$mailer->setFrom('from@example.com', 'Mailer');
$mailer->addAddress('joe@example.net', 'Joe User');     // Add a recipient
$mailer->addAddress('ellen@example.com');               // Name is optional
$mailer->addReplyTo('info@example.com', 'Information');
$mailer->addCC('cc@example.com');
$mailer->addBCC('bcc@example.com');

$mailer->addAttachment('/var/tmp/file.tar.gz');         // Add attachments
$mailer->addAttachment('/tmp/image.jpg', 'new.jpg');    // Optional name
$mailer->isHTML(true);                                  // Set email format to HTML

$mailer->Subject = 'Here is the subject';
$mailer->Body    = 'This is the HTML message body <b>in bold!</b>';
$mailer->AltBody = 'This is the body in plain text for non-HTML mail clients';
```

...but then before sending, specify a file with the keys you want to use (optional) and the encryption / signing options you want to use:

```php
// Optionally specify a file that contains the keys you want to use.
// Not necessary if the key was already imported into gnupg previously (or manually).
$mailer->importKeyFile('/path/to/my-gpg-keyring.asc');

// Optionally check if there is an encryption key for the given recipient(s).
// People not knowing about OpenPGP might be confused by OpenPGP signed mails, 
// so putting `pgpSign()` in an if-statement might be a good idea.
if (count($mailer->getKeys('joe@example.net', 'encrypt')) === 1) {

    // Turn on encryption for your email
    $mailer->encrypt(true);
    
    // Turn on signing for your email
    $mailer->pgpSign(true);
}

// Turn on protected headers for your email (not supported by all OpenPGP supporting clients)
$mailer->protectHeaders(true);
```

...and then continue normal PHPMailer operation:

```php
// Send!
if (!$mailer->send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mailer->ErrorInfo;
} else {
    echo 'Message has been sent';
}
```

### Key Lookup and Import

```php
$mailer = new PHPMailerPGP();
$errCode = 0;
$key = $mailer->lookupKeyServer('test@example.com', 'keys.openpgp.org', $errCode);
if ($errCode === PHPMailerPGP::LOOKUP_ERR_OK) {
    $mailer->importKey($key);
} // else: not found or error occurred

// now you can send encrypted e-mails to test@example.com
```
