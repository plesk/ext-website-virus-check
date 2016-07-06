<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.

class Modules_WebsiteVirusCheck_PleskDomain
{
    function __construct($id, $name, $ascii_name, $status, $dns_ip_address, $htype, $webspace_id) {
        $this->id = $id;
        $this->name = $name;
        $this->ascii_name = $ascii_name;
        $this->status = $status;
        $this->available = 'unknown';
        $this->dns_ip_address = $dns_ip_address;
        $this->htype = $htype;
        $this->webspace_id  = $webspace_id ? $webspace_id : $id;
    }
    
    /**
     * @return bool
     */
    private function isResolvingToPlesk() {
        /*
           array(5) {
              [0]=>
                array(5) {
                    ["host"]=>  string(9) "gmail.com"
                    ["class"]=> string(2) "IN"
                    ["ttl"]=>   int(147)
                    ["type"]=>  string(1) "A"
                    ["ip"]=>    string(14) "173.194.222.17"
                  }
              [4]=>
              array(5) {
                ["host"]=>      string(9) "gmail.com"
                ["class"]=>     string(2) "IN"
                ["ttl"]=>       int(87)
                ["type"]=>      string(4) "AAAA"
                ["ipv6"]=>      string(22) "2a00:1450:4010:c07::11"
              }
            }
         */
        if (!$this->ascii_name) {
            return false;
        }
        
        try {
            $records = @dns_get_record($this->ascii_name, DNS_A|DNS_AAAA);
        } catch (Exception $e) {
            pm_Log::debug(print_r($this, 1) . ' : ' . $e->getMessage());
            return false;
        }
        pm_Log::debug('dns_get_record for ' . $this->ascii_name . ' : ' . print_r($records, 1));
        
        if (!$records) {
            return false;
        }
        foreach ($records as $r) {
            $ip = '';
            if (isset($r['ip'])) {
                $ip = $r['ip'];
            } elseif (isset($r['ipv6'])) {
                $ip = $r['ipv6'];
            }
            foreach ($this->dns_ip_address as $domain_ip) {
                if ($ip === $domain_ip) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @return bool
     */
    public function isAvailable() {
        $this->available = 'no';
        if ($this->status > 0) {
            return false;
        } elseif (!$this->isResolvingToPlesk()) {
            return false;
        }

        $this->available = 'yes';
        return true;
    }

    /**
     * @return string
     */
    public function getAvailable() {
        return pm_Locale::lmsg($this->available);
    }
}