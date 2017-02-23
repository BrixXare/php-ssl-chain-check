<?php
namespace Splitice;


use GuzzleHttp\Client;
use phpseclib\File\X509;
use Radical\Utility\SSL\X509Certificate;

class SSLChainCheck
{
	const END_CERT = '-----END CERTIFICATE-----';
	/**
	 * @param array      $array
	 * @param int|string $position
	 * @param mixed      $insert
	 */
	private function array_insert(&$array, $position, $insert)
	{
		if (!is_numeric($position)) {
			$position   = array_search($position, array_keys($array));
		}

		$array = array_merge(
			array_slice($array, 0, $position),
			[$insert],
			array_slice($array, $position)
		);
	}

	function check($data){
		if(!preg_match('`-----END CERTIFICATE-----[\r\n]*$`',$data) || !preg_match('`^[\r\n]*-----BEGIN CERTIFICATE-----`', $data)){
			throw new \Exception('Certificate has invalid format');
		}

		$x509 = new X509();
		foreach(glob('/etc/ssl/certs/*.pem') as $cert){
			$x509->loadCA(file_get_contents($cert));
		}

		$data = str_replace("\r\n","\n",$data);
		/** @var X509Certificate[] $certs */
		$certs = array();
		foreach(explode("-----BEGIN CERTIFICATE-----\n",$data) as $k=>$cert){
			$cert = trim($cert);
			if($k == 0 && empty($cert)){
				continue;
			}
			$last = strrpos($cert, self::END_CERT);
			if(!$last || strpos($cert, self::END_CERT) != $last || strlen(self::END_CERT) + $last != strlen($cert)){
				throw new \Exception('Certificate has invalid format, end marker invalid');
			}
			$cert = "-----BEGIN CERTIFICATE-----\n$cert";
			$cert = new X509Certificate($cert, $x509);
			$certs[] = $cert;
		}

		$certs_before = $certs;
		for($i=0;$i<10;$i++) {
			$pos = -1;
			$seen_parents = $seen_subjects = array();
			for ($k1 = 0; $k1 < count($certs); $k1++) {
				$c1 = $certs[$k1];
				$pos++;
				$parent_ext = $c1->getExtension('id-ce-authorityKeyIdentifier');
				if(!$parent_ext){
					continue;
				}
				$parent_id = $parent_ext['keyIdentifier'];
				$subject_id = $c1->getExtension('id-ce-subjectKeyIdentifier');

				//Possibly a root CA certificate might have an empty parent? Why is this bundled!
				if(empty($subject_id) || empty($parent_id)){
					continue;
				}

				if (isset($seen_subjects[$parent_id])) {
					$this->array_insert($certs, $seen_subjects[$parent_id], $c1);
					unset($certs[$k1 + 1]);
					$certs = array_values($certs);
					echo 'Re-aranged (subject), swapped ' . $k1 . ' with ', $seen_subjects[$parent_id], "\r\n";
				} elseif (isset($seen_parents[$subject_id]) && $seen_parents[$subject_id] + 1 != $k1) {
					$this->array_insert($certs, $seen_parents[$subject_id] + 1, $c1);
					unset($certs[$k1 + 1]);
					$certs = array_values($certs);
					echo 'Re-aranged (parent), swapped ' . $k1 . ' with ', $seen_parents[$subject_id] + 1, "\r\n";
				}

				$seen_parents[$parent_id] = $pos;
				$seen_subjects[$subject_id] = $pos;
			}
			if($certs == $certs_before){
				break;
			}else{
				$certs_before = $certs;
			}
		}

		$httpClient = new Client();
		$seen_subjects = array();
		for ($k1 = count($certs) - 1; $k1 >= 0; $k1--) {
			$cert = $certs[$k1];
			$subject_id = $cert->getExtension('id-ce-subjectKeyIdentifier');
			$seen_subjects[$subject_id] = true;

			if($cert->isSigned()){
				continue;
			}

			$parent_ext = $cert->getExtension('id-ce-authorityKeyIdentifier');
			if(!$parent_ext){
				continue;
			}
			$parent_id = $parent_ext['keyIdentifier'];

			if(!empty($parent_id) && !isset($seen_subjects[$parent_id])){
				//Not seen, try to download
				$url = $cert->getParentCertificateURL();
				if(empty($url)){
					continue;
				}
				$httpResponse = $httpClient->get($url);

				if ($httpResponse->getStatusCode() != 200) {
					throw new \Exception('Tried to fix certificate chain but could not download certifcate at ' . $cert->getParentCertificateURL());
				}

				$body = (string)$httpResponse->getBody();
				if(strpos($body, '-----BEGIN CERTIFICATE-----') === false){
					$body = "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($body), 64)."-----END CERTIFICATE-----";
				}
				$certificate = new X509Certificate($body, $x509);
				$this->array_insert($certs, $k1 + 1, $certificate);
				$k1 += 2;//this will scan this one again, but whatever
				unset($seen_subjects[$subject_id]);//Just to be safe
			}
		}

		$chain_data = '';
		foreach($certs as $cert){
			$chain_data .= $cert->getContents();
		}

		return $chain_data;
	}
}