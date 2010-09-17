<?php
require_once 'PHPUnit/Framework.php';
require_once 'PHPUnit/Extensions/OutputTestCase.php';
require_once 'Cert.php';

/**
 * Test class for WerxLtd_Auth_Cert.
 */
class WerxLtd_Auth_CertTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var WerxLtd_Auth_Cert
     */
    protected $object;
	
    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp() {
    	$this->object = new WerxLtd_Auth_Cert();
    }
    
    public function testCreate() {
    	$this->assertNotNull($this->object, "Object creation failed");
    	
    	$this->assertType('WerxLtd_Auth_Cert', $this->object, 'Object type incorrect');
    }
    
    public function testGetPKCS12SelfSigned() {
    	$countryName = "US";
		$stateOrProvinceName = "Georgia";
		$localityName = "Roswell";
		$organizationName = "Werx Limited";
		$organizationalUnitName = "";
		$commonName = "Wes Widner";
		$emailAddress = "wes@werxltd.com";
    	
    	$pks12 = $this->object->getPKCS12SelfSigned(
    		$countryName,
			$stateOrProvinceName,
			$localityName,
			$organizationName,
			$organizationalUnitName,
			$commonName,
			$emailAddress
		);
		
    	$this->assertNotNull($pks12, "PKCS12 cert not generated properly");
    	
    	openssl_pkcs12_read($pks12, $data, null);
    	
    	$this->assertNotNull($data, "PKCS12 Data not read properly");
    	
    	$this->assertNotNull($data['cert'], "PKCS12 Cert data does not exist");
    	
    	$certdata = openssl_x509_parse($data['cert']);
    	
    	$this->assertEquals($certdata['subject']['C'], $countryName, "PKCS12 Country does not match");
    	$this->assertEquals($certdata['subject']['ST'], $stateOrProvinceName, "PKCS12 State does not match");
    	$this->assertEquals($certdata['subject']['L'], $localityName, "PKCS12 Locality does not match");
    	$this->assertEquals($certdata['subject']['O'], $organizationName, "PKCS12 Orginization name does not match");
    	$this->assertEquals($certdata['subject']['OU'], $organizationalUnitName, "PKCS12 Orginization unit name does not match");
    	$this->assertEquals($certdata['subject']['CN'], $commonName, "PKCS12 Common name does not match");
    	$this->assertEquals($certdata['subject']['emailAddress'], $emailAddress, "PKCS12 Email address does not match");
    }
    
    public function testGetClientCertData() {
    	$countryName = "US";
		$stateOrProvinceName = "Georgia";
		$localityName = "Roswell";
		$organizationName = "Werx Limited";
		$organizationalUnitName = "";
		$commonName = "Wes Widner";
		$emailAddress = "wes@werxltd.com";
    	
    	$_SERVER['SSL_CLIENT_CERT'] = '-----BEGIN CERTIFICATE-----
MIIDgDCCAumgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBjTELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkdBMRMwEQYDVQQHEwpBbHBoYXJldHRhMQ8wDQYDVQQKEwZNY0Fm
ZWUxDTALBgNVBAsTBExhYnMxEzARBgNVBAMTCldlcyBXaWRuZXIxJzAlBgkqhkiG
9w0BCQEWGHdlc2xleV93aWRuZXJAbWNhZmVlLmNvbTAeFw0xMDA5MTMyMTA0MTVa
Fw0xMTA5MTMyMTA0MTVaMIGNMQswCQYDVQQGEwJVUzELMAkGA1UECBMCR0ExEzAR
BgNVBAcTCkFscGhhcmV0dGExDzANBgNVBAoTBk1jQWZlZTENMAsGA1UECxMETGFi
czETMBEGA1UEAxMKV2VzIFdpZG5lcjEnMCUGCSqGSIb3DQEJARYYd2VzbGV5X3dp
ZG5lckBtY2FmZWUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvrLdC
mJsswx43mNO3/sD9YRB2f5eQ/le7i9flbJrX3pAP8ycx6WHkOXsu0FYdjNW4a6KR
7hTfqms2lLS/w4UrJJmBDVc63hxwygAo0Ydp2TvfFmKzIOFvZxqxCQzf7PoqMKj3
d5ARvmKmFkRsd81sNaB+3mv1A4T2aOxXXwM+pQIDAQABo4HtMIHqMB0GA1UdDgQW
BBSWy5EgNh5y0zi4b+ARUcch1cjHZTCBugYDVR0jBIGyMIGvgBSWy5EgNh5y0zi4
b+ARUcch1cjHZaGBk6SBkDCBjTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkdBMRMw
EQYDVQQHEwpBbHBoYXJldHRhMQ8wDQYDVQQKEwZNY0FmZWUxDTALBgNVBAsTBExh
YnMxEzARBgNVBAMTCldlcyBXaWRuZXIxJzAlBgkqhkiG9w0BCQEWGHdlc2xleV93
aWRuZXJAbWNhZmVlLmNvbYIBADAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBAUA
A4GBAAUszXaGP4KlNafbr1TI5g5pZh/bsDCVX9mSuLQvgrMBUQHkT36K3CA1VyCI
7iPJDixloQAXEkErp5zGs5NDaj2vCTB1QC4FKHC4cNRj72g7chC3MPu5p5ULsaQ6
hCkfk1Ff6iVehmUCmBJAvhtawZQXSoC+OT5DW1Mna1EUQouj
-----END CERTIFICATE-----
';
    	
    	$this->object->parseClientData();
    	
    	$certdata = $this->object->getClientCertData();
    	
    	$this->assertTrue(is_array($certdata),"Client certificate did not validate properly");
    	
    	$this->assertEquals($certdata['subject']['C'], $countryName, "PKS12 Country does not match");
    	$this->assertEquals($certdata['subject']['ST'], $stateOrProvinceName, "PKS12 State does not match");
    	$this->assertEquals($certdata['subject']['L'], $localityName, "PKS12 Locality does not match");
    	$this->assertEquals($certdata['subject']['O'], $organizationName, "PKS12 Orginization name does not match");
    	$this->assertEquals($certdata['subject']['OU'], $organizationalUnitName, "PKS12 Orginization unit name does not match");
    	$this->assertEquals($certdata['subject']['CN'], $commonName, "PKS12 Common name does not match");
    	$this->assertEquals($certdata['subject']['emailAddress'], $emailAddress, "PKS12 Email address does not match");
    	
    	$this->assertTrue($this->object->isClientCertSelfSigned(), "Self signed status invalid");
    }
}