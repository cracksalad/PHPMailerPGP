<?php

namespace PHPMailer\PHPMailerPGP;

/**
 * @author  Travis Richardson (@ravisorg)
 * @author Andreas Wahlen
 * @license http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
trait PGPHelper
{
    /**
     * @var \gnupg|null
     */
    protected $gnupg = null;

    /**
     * Specifies the home directory for the GnuPG keyrings. By default this is the user's home
     * directory + /.gnupg, however when running on a web server (eg: Apache) the home directory
     * will likely not exist and/or not be writable. Set this by calling setGPGHome before calling
     * any other encryption/signing methods.
     * @var string
     * @see PHPMailerPGP::setGPGHome()
     */
    protected $gnupgHome = '';

    /**
     * Initializes the GnuPG class after checking to make sure it's available. Called by anything
     * that uses the GnuPG methods before they attempt anything.
     * @throws PHPMailerPGPException
     * @return void
     */
    protected function initGNUPG()
    {
        if (!class_exists('gnupg')) {
            throw new PHPMailerPGPException('PHPMailerPGP requires the GnuPG class');
        }

        if ($this->gnupgHome === '' && isset($_SERVER['HOME'])) {
            $this->gnupgHome = $_SERVER['HOME'] . '/.gnupg';
        }
        if ($this->gnupgHome === '' && getenv('HOME')) {
            $this->gnupgHome = getenv('HOME') . '/.gnupg';
        }
        if ($this->gnupgHome === '') {
            throw new PHPMailerPGPException('Unable to detect GnuPG home path, please call PHPMailerPGP::setGPGHome()');
        }
        if (!file_exists($this->gnupgHome)) {
            throw new PHPMailerPGPException('GnuPG home path does not exist');
        }
        putenv('GNUPGHOME=' . escapeshellcmd($this->gnupgHome));

        if (!$this->gnupg) {
            /**
             * @psalm-var \gnupg $this->gnupg
             */
            $this->gnupg = new \gnupg();
        }
        $this->gnupg->seterrormode(\gnupg::ERROR_EXCEPTION);
    }

    /**
     * Sets the home directory for the GnuPG keyrings. By default this is the user's home
     * directory + /.gnupg, however when running on a web server (eg: Apache) the home directory
     * will likely not exist and/or not be writable. Call this before calling any other encryption
     * /signing methods if needed.
     * @param string $home The complete path to the GnuPG keyring directory (eg: $HOME/.gnupg)
     * @throws PHPMailerPGPException
     * @return void
     */
    public function setGPGHome($home)
    {
        if (!file_exists($home)) {
            throw new PHPMailerPGPException('Specified path does not exist');
        }
        $this->gnupgHome = $home;
    }
}
