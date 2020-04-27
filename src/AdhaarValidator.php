<?php


namespace janruls1\AdhaarValidator;

use Carbon\Carbon;
use RuntimeException;

class AdhaarValidator
{
    protected const a = 'sha256';
    protected const d =
        [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        ];
    protected const p =
        [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
        ];

    protected $xml;
    protected $adhaarInfo = [];
    protected $adhaarRefNo;
    protected $share_code;

    public function __construct(string $xml = '', string $share_code = '')
    {
        $this->xml = $xml;
        $this->share_code = $share_code;
        if ($this->xml) {
            $this->parseAdhaar();
        }
    }

    private function getIteratedHash (int $iterations, string $string): string
    {
        $hashingIterations = 0;
        // for 0 and 1 it'll hash 1 times and for rest it'll hash for exact no.
        do {
            $string = hash(self::a, $string);
            $hashingIterations++;
        } while ($hashingIterations < $iterations);

        return $string;
    }

    private function processNodeAdhaar ($node): AdhaarValidator
    {
        $result = [];

        foreach ($node->attributes() as $key => $value)
        {
            $result[$key] = (string)$value;
        }

        $this->adhaarInfo[strtolower($node->getName())] = $result;

        return $this;
    }

    private function parseAdhaar (): AdhaarValidator
    {
        if (!$this->xml) {
            throw new RuntimeException('No XML provided');
        }

        $xml = simplexml_load_string($this->xml);

        if (!$xml->UidData->Poi) {
            throw new RuntimeException('No POI in provided XML');
        }

        $this->processNodeAdhaar($xml->UidData->Poi);

        if (!$xml->UidData->Poa) {
            throw new RuntimeException('No POA in provided XML');
        }

        $this->processNodeAdhaar($xml->UidData->Poa);

        if (!$xml->UidData->Pht) {
            throw new RuntimeException('No PHOTO in provided XML');
        }

        $this->adhaarInfo['pht'] = (string)$xml->UidData->Pht;

        if (!$xml->attributes()['referenceId']){
            throw new RuntimeException('Malformed XML');
        }

        $this->adhaarRefNo = (string)$xml->attributes()['referenceId'];

        $this->adhaarInfo['meta'] = [
            'lastAdhaarDigits' => substr($this->adhaarRefNo, 0, 4),
            'adhaarGeneratedAt' => Carbon::createFromFormat("YmdHisv", substr($this->adhaarRefNo, 4, -1))->roundSecond()
        ];

        return $this;
    }

    public function getAdhaarData (): array
    {
        return $this->adhaarInfo;
    }

    public function validateAdhaarPhoneNumber (string $mobile_no): bool
    {
        if (!$this->share_code) {
            throw new RuntimeException('No share code provided');
        }
        return $this->adhaarInfo['poi']['m'] === $this->getIteratedHash((int)$this->adhaarInfo['meta']['lastAdhaarDigits'][3], $mobile_no.$this->share_code);
    }

    public function validateAdhaarEmailId (string $email): bool
    {
        if (!$this->share_code) {
            throw new RuntimeException('No share code provided');
        }

        $adhaar_email = $this->adhaarInfo['poi']['e'];
        // For cases where email is not attached to adhaar
        if ($adhaar_email === '')
        {
            return true;
        }
        return $adhaar_email === $this->getIteratedHash((int)$this->adhaarInfo['meta']['lastAdhaarDigits'][3], $email.$this->share_code);
    }

    public function validateAdhaarXml (): bool
    {
        $certPath = config('adhaar-validator.certificate_path');
        $signatureValidator = new XmlSignatureValidator();
        $signatureValidator->loadPublicKeyFile($certPath);

        return $signatureValidator->verifyXmlFile($this->xml);
    }

    public static function _validateAdhaarXml (string $xml): bool
    {
        try {
            return (new self($xml))->validateAdhaarXml();
        } catch (RuntimeException $e) {
            // This is just a validators, hence don't throw errors from here
            return false;
        }
    }

    public static function _validateAdhaarNo (string $adhaar_no): bool
    {
        return strlen($adhaar_no) === 12 && self::validateVerhoeff($adhaar_no);
    }

    private static function validateVerhoeff (string $num): bool
    {
        $c = 0;
        $myArray = self::stringToReversedIntArray($num);
        foreach ($myArray as $i => $iValue) {
            $c = self::d[$c][self::p[($i % 8)][$iValue]];
        }

        return ($c === 0);
    }

    private static function stringToReversedIntArray (string $num): array
    {
        $myArray = [];
        for ($i = 0, $loopsMax = strlen($num); $i < $loopsMax; $i++) {
            $myArray[$i] = (int)$num[$i];
        }

        return array_reverse($myArray);
    }
}
