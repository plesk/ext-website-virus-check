<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.

class Modules_WebsiteVirusCheck_SettingsForm extends pm_Form_Simple
{
    /**
     * Validate the form
     *
     * @param  array $data
     * @return boolean
     */
    function isValid($data)
    {
        $baseValid = parent::isValid($data);
        
        $virustotal_api_key = $this->getElement('virustotal_api_key')->getValue();
        $virustotal_enabled = $this->getElement('virustotal_enabled')->getValue();
        $promo_enabled = $this->getElement('_promo_admin_home')->getValue();

        if ($virustotal_enabled) {
            if (!$baseValid) {
                return false;
            }
            
            $isKey = Modules_WebsiteVirusCheck_Helper::checkApiKey($virustotal_api_key);
            if ($isKey['valid']) {
                return true;
            }
            $msg = pm_Locale::lmsg(
                'settingsFormApiCheckError',
                [
                    'http_code'  => (string)$isKey['http_code'],
                    'http_error' => (string)$isKey['http_error'],
                ]
            );

            if ($isKey['http_code']) {
                $msg = pm_Locale::lmsg(
                    'settingsFormApiInvalid',
                    [
                        'http_code'  => (string)$isKey['http_code'],
                        'http_error' => (string)$isKey['http_error'],
                    ]
                );
            }

            $this->getElement('virustotal_api_key')->addError($msg);
            $this->markAsError();

            return false;
        }

        return true;
    }
}