<?php

namespace Ekapusta\OAuth2Esia\Security\Signer;

use Ekapusta\OAuth2Esia\Security\Signer;
use Ekapusta\OAuth2Esia\Security\Signer\Exception\SignException;

class OpensslPkcs7 extends Signer
{
    public function sign($message)
    {
        try {            
            $mfr = tempnam ( '/tmp' , 'cspr_' );
            $mfw = tempnam ( '/tmp' , 'cspw_' );
            $myfile = fopen($mfr, 'w');
            fwrite($myfile, $message);
            fclose($myfile);
            
            shell_exec('/opt/cprocsp/bin/amd64/csptest -sfsign -sign -in '.$mfr.' -out '.$mfw.' -my "'.ESIA_KEY_ID.'" -detached -password "'.ESIA_KEY_PASSWORD.'" -add');
        
            $myfile = fopen($mfw, "r");
            $sm = fread($myfile,filesize($mfw));
            fclose($myfile);
            unlink($mfr);
            unlink($mfw);
        
            return $sm;
        } catch (Exception $e) {
            throw SignException::signFailedAsOf("Ошибка подписи сообщения к ЕСИА!");
        }    
    }
}
