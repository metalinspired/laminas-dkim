README
========

Laminas Project DKIM Signer.

**Note**

Based on [joepsyko/zf-dkim](https://github.com/joepsyko/zf-dkim)

**Installation**

<code>composer require metalinspired/laminas-dkim</code>

Create a *./config/autoload/dkim.global.php* and *./config/autoload/dkim.local.php* file with the configuration variable values as described in the project *.dist* files.

**Usage**

1. Create a DKIM domain key 
   - See: [http://dkimcore.org/specification.html](http://dkimcore.org/specification.html "dkimcore.org")

2. Configure the DkimSigner using the config.dist file

3. Sign & send

```
$mail = new \Laminas\Mail\Message();
$mail->setBody("Hello world!");
$mail->setFrom('from@example.com');
$mail->addTo('to@example.com');
$mail->setSubject('subject');

// Sign message with dkim
$signer = $this->getServiceLocator()->get(\Dkim\Signer\Signer::class);
$signer->signMessage($mail);

// Send message
$transport = new \Laminas\Mail\Transport\Sendmail();
$transport->send($mail);
```
