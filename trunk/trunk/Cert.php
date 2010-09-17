<?php

/*
 *
 * @author Wes Widner
 */

final class WerxLtd_Auth_Cert {
	private $publickey;
	private $config;
	private $csr;
	private $privkeypass;    //password for private key
	private $csr_days_valid;
	private $client_cert_data;
	
	public function __construct() {
		if(!defined("CERT_INI"))  define('CERT_INI', dirname(__FILE__).'/cert.ini');

		if(!file_exists(CERT_INI)) {
			die("cert.ini file not found at ".CERT_INI);
		}
			
		$certcfg = parse_ini_file(CERT_INI, true);

		$this->config = array("config" => $certcfg['open_ssl_conf_path']);
		$this->csr_days_valid = $certcfg['crt_days_valid'];
		$this->privkeypass = $certcfg['private_key_passphrase'];
		
	    $this->parseClientData();
	}

	public function parseClientData() {
	    if($this->hasClientCert()) {
	        $this->client_cert_data = openssl_x509_parse($_SERVER['SSL_CLIENT_CERT']);
	    }
	}
	
	/**
     * get an attr
     * @param <type> $value
     * @return <type>
     */
    public function &__get($value) {
        return $this->attr[$value];
    }

    /**
     * set an attr
     *
     * @param <type> $key
     * @param <type> $value
     * @return <type>
     */
    public function __set($key, $value) {
        $this->attr[$key] = $value;
    }
	
	/**
     * Used for getXXX and setXXX only
     *
     * @param <type> $fnc
     * @param <type> $args
     * @return <type>
     */
    public function __call($fnc, $args) {
        if(substr($fnc, 0, 3) == 'get') {
            $get = lcfirst(substr($fnc, 3));
            return $this->$get;
        }

        if(substr($fnc, 0, 3) == 'set') {
            $set = lcfirst(substr($fnc, 3));
            $this->$set = $args[0];
        }
    }
    
	public function getClientCertData() {
		return $this->client_cert_data;
	}
    
	public function isClientCertSelfSigned() {
	    if(!isset($this->client_cert_data) || !is_array($this->client_cert_data)) return FALSE;
	    
	    return $this->client_cert_data['subject'] == $this->client_cert_data['issuer'];
	}
	
	function readf($path){
        //return file contents
        $fp=fopen($path,"r");
        $ret=fread($fp,8192);
        fclose($fp);
        return $ret;
    }
    
    //privatekey can be text or file path
    function set_privatekey($privatekey, $isFile=0, $key_password=""){
        
        if ($key_password) $this->privkeypass=$key_password;
        
        if ($isFile)$privatekey=$this->readf($privatekey);
        
        $this->privatekey=openssl_get_privatekey($privatekey, $this->privkeypass);
    }
    
    //publickey can be text or file path
    function set_publickey($publickey, $isFile=0){
        
        if ($isFile)$publickey=$this->readf($publickey);
        
        $this->publickey=openssl_get_publickey($publickey);
    }
	
    public function hasClientCert() {
        return array_key_exists('SSL_CLIENT_CERT', $_SERVER);
    }
    
    public function getSubjectKeyIdentifier() {
        return $this->client_cert_data['extensions']['subjectKeyIdentifier'];
    }
    
    public function getPKCS12SelfSigned(
            $countryName,
			$stateOrProvinceName,
			$localityName,
			$organizationName,
			$organizationalUnitName,
			$commonName,
			$emailAddress
		) {
		
		$dn=array(
                    "countryName" => $countryName,
                    "stateOrProvinceName" => $stateOrProvinceName,
                    "localityName" => $localityName,
                    "organizationName" => $organizationName,
                    "organizationalUnitName" => $organizationalUnitName,
                    "commonName" => $commonName,
                    "emailAddress" => $emailAddress,
                    "extendedKeyUsage" => "clientAuth",
		            "authorityInfoAccess" => "URI:http://".getenv('HTTP_HOST')."/"
		);
		
		$privkey = openssl_pkey_new($this->config);
		$csr = openssl_csr_new($dn, $privkey, $this->config);
		$sscert = openssl_csr_sign($csr, null, $privkey, $this->csr_days_valid, $this->config); // Self signed
		openssl_x509_export($sscert, $this->publickey);
    	openssl_pkcs12_export($this->publickey, $pks12, $privkey, null);
    	return $pks12;
    }
    
    
}