<?php

use Splitice\SSLChainCheck;

class SSLChainCheckValidateTest extends \PHPUnit\Framework\TestCase
{
	function testAlphaNum()
	{
		$this->expectException(\Exception::class);
		$cert = 'abcde09';
		$sslChainCheck = new SSLChainCheck();
		$sslChainCheck->check($cert);
	}
	function testBlank(){
		$this->expectException(\Exception::class);
		$cert = '';
		$sslChainCheck = new SSLChainCheck();
		$sslChainCheck->check($cert);
	}
	function testEmptyOneStart(){
		$this->expectException(\Exception::class);
		$cert = '-----BEGIN CERTIFICATE-----';
		$sslChainCheck = new SSLChainCheck();
		$sslChainCheck->check($cert);
	}
	function testEmptyTwoStart(){
		$this->expectException(\Exception::class);
		$cert = "-----BEGIN CERTIFICATE-----\r\n-----BEGIN CERTIFICATE-----\r\n";
		$sslChainCheck = new SSLChainCheck();
		$sslChainCheck->check($cert);
	}
	function testEmptyDoubleStart(){
		$this->expectException(\Exception::class);
		$cert = "-----BEGIN CERTIFICATE-----\r\n-----END CERTIFICATE-----\r\n";
		$sslChainCheck = new SSLChainCheck();
		$sslChainCheck->check($cert);
	}
	function testNoBeginEnd(){
		$this->expectException(\Exception::class);
		$cert = file_get_contents(__DIR__.'/../certs/valid_no_beginend.pem');
		$sslChainCheck = new SSLChainCheck();
		$sslChainCheck->check($cert);
	}
	function testAppendNoBeginEnd(){
		$this->expectException(\Exception::class);
		$cert = file_get_contents(__DIR__.'/../certs/valid_self_signed.pem')."\r\n".file_get_contents(__DIR__.'/../certs/valid_no_beginend.pem');
		$sslChainCheck = new SSLChainCheck();
		$sslChainCheck->check($cert);
	}
    function testDoubleBegin(){
        $this->expectException(\Exception::class);
        $cert = "-----BEGIN CERTIFICATE-----\r\n".file_get_contents(__DIR__.'/../certs/test_cert_nochain.pem');
        $sslChainCheck = new SSLChainCheck();
        $sslChainCheck->check($cert);
    }
	function testValidSelfSigned(){
		$cert = file_get_contents(__DIR__.'/../certs/valid_self_signed.pem');
		$sslChainCheck = new SSLChainCheck();
		$this->assertEquals(trim($cert),trim($sslChainCheck->check($cert)));
	}
	function testValidSelfSignedNl1(){
		$cert = file_get_contents(__DIR__.'/../certs/valid_self_signed.pem')."\r\n\n\r\n";
		$sslChainCheck = new SSLChainCheck();
		$this->assertEquals(trim($cert),trim($sslChainCheck->check($cert)));
	}
	function testValidSelfSignedNl2(){
		$cert = "\r\n\n\r\n".file_get_contents(__DIR__.'/../certs/valid_self_signed.pem');
		$sslChainCheck = new SSLChainCheck();
		$this->assertEquals(trim($cert),trim($sslChainCheck->check($cert)));
	}
	function testNoChain(){
		$cert = file_get_contents(__DIR__.'/../certs/test_cert_nochain.pem');
		$sslChainCheck = new SSLChainCheck();
		$result = trim($sslChainCheck->check($cert));
		$expected = trim(file_get_contents(__DIR__.'/../certs/test_cert_chain.pem'));

		$this->assertContains(str_replace("\r",'',$expected), str_replace("\r",'',$result));
	}
}
