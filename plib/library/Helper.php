<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.

class Modules_WebsiteVirusCheck_Helper
{
    const virustotal_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan';
    const virustotal_report_url = 'https://www.virustotal.com/vtapi/v2/url/report';
    const virustotal_report_domain = 'https://www.virustotal.com/vtapi/v2/domain/report';
    const virustotal_domain_info_url = 'https://www.virustotal.com/domain/%s/information/';
    const virustotal_api_timeout = 20;
    const virustotal_api_day_limit = 4320;
    const virustotal_api_hour_limit = 180;

    public static function check()
    {           
        if (!pm_Settings::get('virustotal_enabled') || !pm_Settings::get('virustotal_api_key')) {
            return;
        }

        if (pm_Settings::get('apiKeyBecameInvalid')) {
            pm_Log::err(pm_Locale::lmsg('apiKeyBecameInvalid'));
            return;
        }
        
        if (pm_Settings::get('scan_lock')) {
            $last_scan = DateTime::createFromFormat('d/M/Y G:i', pm_Settings::get('last_scan'));
            $now = new DateTime();
            $interval = $now->diff($last_scan);
            if ($interval->h < 1) {
                pm_Log::debug(pm_Locale::lmsg('errorScanAlreadyRunning'));
                return;
            }
        } else {
            pm_Settings::set('scan_lock', 1); // Also set to 0 after check self::is_enough()
        }

        pm_Settings::set('last_scan', date('d/M/Y G:i')); // Has dependency with scan_lock
        
        self::report();
        $i = 1;
        $domains = self::getDomains();
        foreach ($domains as $domain) {
            $i++;

            if (!self::is_last_domain('check', $domain)) {
                continue;
            }

            $report = self::getDomainReport($domain->id);
            if ($report
                && isset($report['virustotal_request_done'])
                && !$report['virustotal_request_done']) {
                continue;
            }
            if ($report && isset($report['domain']['enabled']) && !$report['domain']['enabled']) {
                continue;
            }
            if (!$report) {
                $report = [];
            }

            self::set_progress($i, count($domains) + 1, 2, 2);
            
            if (!$domain->isAvailable()) {
                $report['domain'] = $domain;
                self::setDomainReport($domain->id, $report);
                continue;
            }
            
            if (self::is_enough() || !pm_Settings::get('scan_lock')) {
                pm_Settings::set('scan_lock', 0);
                exit(0);
            }
            $report['domain'] = $domain;
            $report['virustotal_request_done'] = false;
            
            $request = self::virustotal_scan_url_request($domain->ascii_name);
            if (isset($request['http_error'])) {
                $report['http_error'] = $request['http_error'];
            } else {
                $report['virustotal_request'] = array(
                    'response_code' => isset($request['response_code']) ? $request['response_code'] : 0,
                    'scan_date' => isset($request['scan_date']) ? $request['scan_date'] : '',
                );
            }

            self::setDomainReport($domain->id, $report);
        }
        
        pm_Settings::set('scan_lock', 0);
        
        self::cleanup_last_domains();
        self::cleanup_deleted_domains();
    }

    /**
     * VirusTotal API has restriction in 4 req/min, for safety we have limit to 3 req/min (180 req/hour, 4320 req/day)
     * 
     * @return bool
     */
    public static function is_enough()
    {
        static $counter = 0;
        if ($counter >= self::virustotal_api_hour_limit) {
            return true;
        }
        $counter++;
        return false;
    }

    /**
     * Update progress for long task
     * @param $current int
     * @param $total int
     * @param $phase int
     * @param $phases int
     * @return int
     */
    public static function set_progress($current, $total, $phase, $phases)
    {
        $current_amplification = ($current * ($phase / $phases)) + ($total - ( $total * ($phases - $phase)));
        $total_amplification = $total * ($phases * ($phase / $phases) );

        $progress = ($current_amplification / $total_amplification) * 100;

        pm_Settings::set('scan_progress', $progress);

        if (class_exists('pm_LongTask_Manager')) { // Since Plesk 17.0
            $taskManager = new pm_LongTask_Manager();

            $tasks = $taskManager->getTasks(['task_scan']);
            foreach ($tasks as $task) {
                $task->updateProgress($progress);
            }
        }

        return $progress;
    }

    /**
     * @param  $operation string
     * @param  $domain Modules_WebsiteVirusCheck_PleskDomain
     * @return bool
     */
    public static function is_last_domain($operation, $domain)
    {
        $last = json_decode(pm_Settings::get('last_domain_' . $operation), true);
        if (!$last) {
            pm_Settings::set('last_domain_' . $operation, json_encode($domain));
            return true;
        }

        if ($domain->id < $last['id']) {
            return false;
        }

        pm_Settings::set('last_domain_' . $operation, json_encode($domain));
        return true;
    }

    public static function report()
    {
        $i = 1;
        $domains = self::getDomains();
        foreach ($domains as $domain) {
            $i++;

            if (!self::is_last_domain('report', $domain)) {
                continue;
            }
            $request = self::getDomainReport($domain->id);
            if (!$request) {
                continue;
            }

            if (isset($request['domain']['enabled']) && !$request['domain']['enabled']) {
                continue;
            }

            self::set_progress($i, count($domains) + 1, 1, 2);

            if (self::is_enough() || !pm_Settings::get('scan_lock')) {
                pm_Settings::set('scan_lock', 0);
                exit(0);
            }
            $report = self::virustotal_scan_url_report($domain->ascii_name);
            pm_Log::debug(print_r($report, 1));

            $reportDomain =  self::virustotal_scan_domain_report($domain->ascii_name);
            $report['detected_urls'] = isset($reportDomain['detected_urls']) ? count($reportDomain['detected_urls']): 0;
            $report['detected_communicating_samples'] = isset($reportDomain['detected_communicating_samples']) ? count($reportDomain['detected_communicating_samples']): 0;
            $report['detected_referrer_samples'] = isset($reportDomain['detected_referrer_samples']) ? count($reportDomain['detected_referrer_samples']): 0;

            self::report_domain($domain, $report);
        }
    }

    public static function cleanup_last_domains()
    {
        $ops = ['report', 'check'];
        foreach ($ops as $operation) {
            pm_Settings::set('last_domain_' . $operation, false);
        }
    }

    public static function cleanup_deleted_domains()
    {
        pm_Bootstrap::init();
        $module_id = pm_Bootstrap::getDbAdapter()->fetchOne("select module_id from ModuleSettings where name ='virustotal_enabled'");
        if (!$module_id) {
            return;
        }
        $reports = pm_Bootstrap::getDbAdapter()->fetchAssoc("select name, value from ModuleSettings where module_id = ${module_id} and name like 'domain_id_%'");
        //pm_Log::debug(print_r($reports, 1));

        foreach ($reports as $row) {
            $report = json_decode($row['value'], true);
            try {
                $domain = new pm_Domain($report['domain']['id']);
            } catch (pm_Exception $e) {
                pm_Bootstrap::getDbAdapter()->delete('ModuleSettings', "module_id = ${module_id} AND name = '{$row['name']}'");
            }
        }
    }
    
    /**
     * @param $domain Modules_WebsiteVirusCheck_PleskDomain
     * @param $new_report array
     * @return null
     */
    public static function report_domain($domain, $new_report)
    {
        $report = self::getDomainReport($domain->id);
        if (!$report) {
            $report = [];
        }
        if (isset($new_report['http_error'])) {
            $report['http_error'] = $new_report['http_error'];
        }
        $report['virustotal_request_done'] = true;
        $report['virustotal_response_code'] = isset($new_report['response_code']) ? (int)$new_report['response_code'] : 0;
        $report['virustotal_positives'] = isset($new_report['positives']) ? (int)$new_report['positives'] : 0;
        $report['virustotal_total'] = isset($new_report['total']) ? (int)$new_report['total'] : '';
        $report['virustotal_scan_date'] = isset($new_report['scan_date']) ? $new_report['scan_date'] : '';
        $report['detected_urls'] = $new_report['detected_urls'];
        $report['detected_communicating_samples'] = $new_report['detected_communicating_samples'];
        $report['detected_referrer_samples'] = $new_report['detected_referrer_samples'];

        if ((int)$report['virustotal_positives'] > 0
            || $report['detected_urls'] > 0
            || $report['detected_communicating_samples'] > 0
            || $report['detected_referrer_samples'] > 0) {
            self::sendNotification($domain);
        }

        self::setDomainReport($domain->id, $report);

        return;
    }

    /**
     * @param $client Zend_Http_Client
     * @param $method string
     * @return Zend_Http_Response|Zend_Http_Client_Adapter_Exception|false
     */
    static function send_http_request(Zend_Http_Client $client, $method = Zend_Http_Client::GET) {
        $response = false;

        for ($try = 5; $try > 0; $try--) {
            pm_Log::debug('Try to connect ' . self::virustotal_scan_url);
            try {
                $response = $client->request($method);
                pm_Log::debug('Successfully request ' . $method . ' ' . self::virustotal_scan_url);
                break;
            } catch (Zend_Http_Client_Adapter_Exception $e) {
                pm_Log::err('Failed to request ' . $method . ' ' . self::virustotal_scan_url . $e->getMessage());
                sleep(5);
                return $e;
            }
        }

        return $response;
    }

    /**
     * @param $url string
     * @return array
     */
    public static function virustotal_scan_url_request($url)
    {
        $client = new Zend_Http_Client(self::virustotal_scan_url);

        $client->setParameterPost('url', $url);
        $client->setParameterPost('apikey', pm_Settings::get('virustotal_api_key'));
        sleep(self::virustotal_api_timeout);

        $response = self::send_http_request($client, Zend_Http_Client::POST);
        if ($response === false) {
            return array (
                'http_error' => pm_Locale::lmsg('httpErrorFailedToConnectVirusTotalUnknownError'),
            );
        }
        if ($response instanceof Zend_Http_Client_Adapter_Exception) {
            return array (
                'http_error' => $response->getMessage(),
            );
        }

        if ($response->getStatus() == 403) {
            pm_Settings::set('apiKeyBecameInvalid', '1');    
        }
                
        return json_decode($response->getBody(), true);
    }

    /**
     * https://virustotal.com/ru/documentation/public-api/#getting-url-scans
     *
     * @param $url string
     * @return array
     */
    public static function virustotal_scan_url_report($url)
    {
        $client = new Zend_Http_Client(self::virustotal_report_url);

        $client->setParameterPost('resource', $url);
        $client->setParameterPost('apikey', pm_Settings::get('virustotal_api_key'));

        sleep(self::virustotal_api_timeout);

        $response = self::send_http_request($client, Zend_Http_Client::POST);
        if ($response === false) {
            return array (
                'http_error' => pm_Locale::lmsg('failedToConnectVirusTotalUnknownError'),
            );
        }
        if ($response instanceof Zend_Http_Client_Adapter_Exception) {
            return array (
                'http_error' => $response->getMessage(),
            );
        }

        if ($response->getStatus() == 403) {
            pm_Settings::set('apiKeyBecameInvalid', '1');
        }

        return json_decode($response->getBody(), true);
    }

    /**
     * https://virustotal.com/ru/documentation/public-api/#getting-domain-reports
     *
     * @param $domainAsciiName string
     * @return array
     */
    public static function virustotal_scan_domain_report($domainAsciiName)
    {
        $client = new Zend_Http_Client(self::virustotal_report_domain);

        $client->setParameterGet('domain', $domainAsciiName);
        $client->setParameterGet('apikey', pm_Settings::get('virustotal_api_key'));

        sleep(self::virustotal_api_timeout);

        $response = self::send_http_request($client, Zend_Http_Client::GET);
        if ($response === false) {
            return array (
                'http_error' => pm_Locale::lmsg('failedToConnectVirusTotalUnknownError'),
            );
        }
        if ($response instanceof Zend_Http_Client_Adapter_Exception) {
            return array (
                'http_error' => $response->getMessage(),
            );
        }

        if ($response->getStatus() == 403) {
            pm_Settings::set('apiKeyBecameInvalid', '1');
        }

        return json_decode($response->getBody(), true);
    }


    /**
     * @return array[string]
     *              ['all']     Modules_WebsiteVirusCheck_PleskDomain[]
     *              ['bad']     Modules_WebsiteVirusCheck_PleskDomain[]
     *              ['total']   int
     */
    public static function getDomainsReport()
    {
        static $domains = [
            'all' => [],
            'bad' => [],
            'total' => 0,
        ];
        if ($domains['total'] > 0) {
            return $domains;
        }
        foreach (self::getDomains() as $domain) {
            $report = self::getDomainReport($domain->id);
            $domain->no_scanning_results = pm_Locale::lmsg('scanningWasNotPerformedYetForList');
            if (!$report) {
                $report = [];
                $report['domain'] = $domain;
                self::setDomainReport($domain->id, $report);
            } else {
                if (isset($report['virustotal_request'])) {
                    $domain->no_scanning_results = pm_Locale::lmsg('scanningRequestIsSent');
                }
                if (isset($report['domain']['enabled'])) {
                    $domain->enabled = $report['domain']['enabled'];
                } else {
                    $domain->enabled = true;
                }
                $domain->available = $report['domain']['available'];
                if ($domain->available == 'no' || (isset($report['virustotal_scan_date']) && $report['virustotal_scan_date'] === '')) {
                    $domain->no_scanning_results = pm_Locale::lmsg('domainInactiveOrCantbeResolvedInHostingIp');
                }
                if (isset($report['http_error'])) {
                    $domain->no_scanning_results = pm_Locale::lmsg('httpError', array('message' => $report['http_error']));
                }
            }
                        
            if (isset($report['virustotal_response_code']) && $report['virustotal_response_code'] > 0) {
                unset($domain->no_scanning_results);
                $domain->virustotal_scan_date = $report['virustotal_scan_date'];
                $domain->virustotal_positives = $report['virustotal_positives'];
                $domain->virustotal_total = $report['virustotal_total'];
                $domain->virustotal_bad_urls_and_samples = $report['detected_urls'] + $report['detected_communicating_samples'] + $report['detected_referrer_samples'];
                $domain->virustotal_domain_info_url = sprintf(self::virustotal_domain_info_url, $domain->ascii_name);
            }

            $domains['all'][$domain->id] = $domain;
            $domains['total']++;
            
            if (!isset($report['virustotal_positives']) || $report['virustotal_positives'] <= 0) {
                continue;
            }
            
            $domains['bad'][$domain->id] = $domain;
        }

        pm_Log::debug('Reports: ' . print_r($domains, 1));
        return $domains;
    }

    /**
     * @return Modules_WebsiteVirusCheck_PleskDomain[]
     */
    public static function getDomains()
    {
        static $domains = [];
        if ($domains) {
            return $domains;
        }
        $sites_request = '<site><get><filter/><dataset><gen_info/></dataset></get></site>';
        $websp_request = '<webspace><get><filter/><dataset><gen_info/></dataset></get></webspace>';
        $api = pm_ApiRpc::getService();
        // site->get->result->[ id, data -> gen_info ( [cr_date] , [name] , [ascii-name] , [status] => 0 , [dns_ip_address] , [htype] )
        $sites_response = $api->call($sites_request);
        $websp_response = $api->call($websp_request);

        $sites = json_decode(json_encode($sites_response->site->get));
        $websp = json_decode(json_encode($websp_response->webspace->get));

        $sites_array =  is_array($sites->result) ? $sites->result : array($sites->result);
        $websp_array =  is_array($websp->result) ? $websp->result : array($websp->result);

        $tmp_list = array_merge($sites_array, $websp_array);

        foreach ($tmp_list as $domain) {
            if (!isset($domain->id)) {
                continue;
            }

            $domains[$domain->id] = new Modules_WebsiteVirusCheck_PleskDomain(
                $domain->id,
                $domain->data->gen_info->name,
                $domain->data->gen_info->{'ascii-name'},
                $domain->data->gen_info->status,
                is_array($domain->data->gen_info->dns_ip_address) ? $domain->data->gen_info->dns_ip_address : array($domain->data->gen_info->dns_ip_address),
                $domain->data->gen_info->htype,
                isset($domain->data->gen_info->{'webspace-id'}) ? $domain->data->gen_info->{'webspace-id'} : $domain->id
            );
        }

        ksort($domains);
        pm_Log::debug('Domains : ' . print_r($domains, 1));
        return $domains;
    }

    /**
     * https://virustotal.com/ru/documentation/public-api/#getting-domain-reports
     *
     * @param $key string
     * @return array
     */
    public static function checkApiKey($key)
    {
        $client = new Zend_Http_Client(self::virustotal_report_url);

        $client->setParameterPost('resource', 'www.virustotal.com');
        $client->setParameterPost('apikey', $key);

        $response = $client->request(Zend_Http_Client::POST);
        $body = json_decode($response->getBody(), true);
        pm_Log::debug('API key check result: ' . print_r($response, 1) . "\n" . print_r($body, 1));
        
        if (isset($body['response_code'])) {
            return [
                'valid' => true,
                'http_code' => $response->getStatus(),
            ];
        }
        
        return [
            'valid' => false,
            'http_code' => $response->getStatus(),
        ];
    }

    /**
     * @param $mail Zend_Mail
     * @return Zend_Mail|false
     */
    static function sendMailRequest($mail)
    {
        $response = false;
        try {
            $response = $mail->send();
        } catch (Zend_Mail_Transport_Exception $e) {
            pm_Log::debug('Failed to send mail');
            pm_Log::err($e);
        }

        return $response;
    }

    /** Send notification to admin
     * @param $domain Modules_WebsiteVirusCheck_PleskDomain
     * @return null
     */
    public static function sendNotification($domain)
    {
        if (!pm_Settings::get('emailNotificationEnabled')) {
            return;
        }
        $today = date('d/M/Y');
        if (pm_Settings::get('notified_id_' . $domain->id) === $today) {
            return;
        }

        pm_Settings::set('notified_id_' . $domain->id, date('d/M/Y'));

        $admin = pm_Client::getByLogin('admin');
        $adminEmail = $admin->getProperty('email');
        $cnameEmail = $admin->getProperty('cname');

        $mail = new Zend_Mail();
        $mail->setBodyText(
            pm_Locale::lmsg(
                'emailNotificationBodyBadDomain',
                [
                    'domain' => $domain->ascii_name,
                    'url' => sprintf(self::virustotal_domain_info_url, $domain->ascii_name)
                ]
            )
        );
        $mail->setFrom($adminEmail, $cnameEmail);
        $mail->addTo($adminEmail, $cnameEmail);
        $mail->setSubject(pm_Locale::lmsg('emailNotificationSubjectBadDomain', ['domain' => $domain->ascii_name]));
        self::sendMailRequest($mail);

        return;
    }

    /** Get domain report by domain id
     * @param $domainId
     * @return mixed
     */
    static function getDomainReport($domainId) {
        $report = json_decode(pm_Settings::get('domain_id_' . $domainId), true);
        $report['detected_urls'] = isset($report['detected_urls']) ? $report['detected_urls'] : 0;
        $report['detected_communicating_samples'] = isset($report['detected_communicating_samples']) ? $report['detected_communicating_samples'] : 0;
        $report['detected_referrer_samples'] = isset($report['detected_referrer_samples']) ? $report['detected_referrer_samples'] : 0;
        return $report;
    }

    /** Set domain report by domain id
     * @param $domainId string
     * @param $report array
     * @return void
     */
    static function setDomainReport($domainId, $report) {
        pm_Settings::set('domain_id_' . $domainId, json_encode($report));
    }
}