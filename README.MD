##Validators
`valid_aadhaar_no` - checks for Verhoeff  
`valid_aadhaar_xml` - checks for adhaar xml digest and signature varification from supplied crt file in config

###Usage
`'adhaar_no' => 'bail|required|valid_aadhaar_no'`,  
`'adhaar_data' => 'bail|required|valid_aadhaar_xml'`,

##Methonds
`AdhaarValidator::_validateAdhaarXml(string $xml):bool` -- same as `valid_aadhaar_xml` validator  
`AdhaarValidator::_validateAdhaarNo(string $adhaar_no):bool` -- same as `valid_aadhaar_no` validator 

`getAdhaarData(): array` -- return supplied adhaar information as

```
[
    'Poi' => array() // Proof of Identity data
    'Poa' => array(), // Proof of Address data
    'Pht' => base64_string, // Image,
    'info' => [
        'lastAdhaarDigits' => string // last 4 digits of adhaar no.
        'adhaarGeneratedAt' => Carbon Instance // Carbon instance for the datetime when the adhaar xml was generated on UIDAI server
    ]
]
```

`validateAdhaarPhoneNumber(string $mobile_no): bool` -- Validates given mobile no against the mobile no. attached with supplied adhaar XML  
`validateAdhaarEmailId(string $email): bool` -- Validates given email against the email attached with supplied adhaar XML


##Usage

```php
$adhaarValidator = new AdhaarValidator($xml, $share_code);
$adhaarValidator->validateAdhaarPhoneNumber('1234567890')
$adhaarValidator->validateAdhaarEmailId('test@test.com')
$adhaarValidator->getAdhaarData()

$adhaarValidator->validateAdhaarXml()
```
