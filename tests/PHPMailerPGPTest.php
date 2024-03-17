<?php
declare(strict_types=1);

namespace PHPMailerPGP\Test;

use PHPMailer\PHPMailerPGP\PHPMailerPGP;
use PHPMailer\PHPMailerPGP\PGPHelper;
use PHPMailer\PHPMailerPGP\PGPKeyManager;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * @author Andreas Wahlen
 * @license http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
#[CoversClass(PHPMailerPGP::class)]
#[CoversClass(PGPHelper::class)]
#[CoversClass(PGPKeyManager::class)]
class PHPMailerPGPTest extends TestCase
{
    private static string $gnupgHome;
    
    private PHPMailerPGP $mailer;
    
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        
        self::$gnupgHome = __DIR__ . '/.gnupg';
        if (!file_exists(self::$gnupgHome)) {
            echo 'GnuPG home did not exist'.PHP_EOL;
            if (!mkdir(self::$gnupgHome)) {
                echo 'unable to create GnuPG home'.PHP_EOL;
            }
        }
        putenv('GNUPGHOME=' . escapeshellcmd(self::$gnupgHome));
        
        $gnupg = new \gnupg();
        if ($gnupg->import(file_get_contents(__DIR__.'/private.key')) === false) {
            echo 'failed to import example key'.PHP_EOL;
        }
    }
    
    protected function setUp(): void
    {
        parent::setUp();

        $this->mailer = new PHPMailerPGP();
        $this->mailer->setGPGHome(self::$gnupgHome);

        $this->mailer->isSMTP();                                      // Set mailer to use SMTP
        $this->mailer->Host = 'smtp1.example.com;smtp2.example.com';  // Specify main and backup SMTP servers
        $this->mailer->SMTPAuth = true;                               // Enable SMTP authentication
        $this->mailer->Username = 'user@example.com';                 // SMTP username
        $this->mailer->Password = 'secret';                           // SMTP password
        $this->mailer->SMTPSecure = 'tls';                            // Enable TLS encryption, `ssl` also accepted
        $this->mailer->Port = 587;                                    // TCP port to connect to

        $this->mailer->setFrom('user@example.com', 'Mailer');
        $this->mailer->addAddress('user@example.com', 'Joe User');     // Add a recipient

        $this->mailer->isHTML(true);                                  // Set email format to HTML
        $this->mailer->Subject = 'Here is the subject';
        $this->mailer->Body    = 'This is the HTML message body <b>in bold!</b>';
        $this->mailer->AltBody = 'This is the body in plain text for non-HTML mail clients';
    }

    private function getBody(): string
    {
        $this->assertTrue($this->mailer->preSend());

        $prop = new \ReflectionProperty($this->mailer, 'MIMEHeader');
        $prop->setAccessible(true);
        $body = $prop->getValue($this->mailer);
        $prop = new \ReflectionProperty($this->mailer, 'MIMEBody');
        $prop->setAccessible(true);
        $body .= $prop->getValue($this->mailer);
        return $body;
    }

    public function testSigning(): void
    {
        $this->mailer->pgpSign(true);

        $body = $this->getBody();

        $this->assertStringContainsString('This is an OpenPGP/MIME signed message (RFC 4880 and 3156)', $body);

        $matches = [];
        $this->assertSame(1, preg_match('/boundary="([^"]+)"/', $body, $matches), 'no boundary found:'.PHP_EOL.$body);
        array_shift($matches);

        foreach($matches as $match){
            // boundary is used as a start marker
            $this->assertSame(1, preg_match('/^--'.preg_quote($match).'\s*$/m', $body), 'start of boundary "'.$match.'" not found: '.PHP_EOL.$body);
            // boundary is used as an end marker
            $this->assertSame(1, preg_match('/^--'.preg_quote($match).'--\s*$/m', $body), 'end of boundary "'.$match.'" not found: '.PHP_EOL.$body);
        }

        $lines = explode(PHPMailerPGP::CRLF, $body);
        for ($i = 0; $i < count($lines); $i++){
            if (strpos($lines[$i], '--') === 0) {
                $j = $i + 1;
                while($j < count($lines) && $lines[$j] !== ''){
                    $this->assertStringStartsNotWith('--', $lines[$j]);
                    $j++;
                }
            }
        }
    }
    
    public function testEncrypt(): void
    {
        $this->mailer->encrypt(true);
        $this->mailer->pgpSign(true);
        $this->mailer->protectHeaders(true);

        $body = $this->getBody();

        $this->assertStringContainsString('This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)', $body);
        $this->assertStringContainsString('-----BEGIN PGP MESSAGE-----', $body);
        $this->assertStringContainsString('-----END PGP MESSAGE-----', $body);
    }
}
