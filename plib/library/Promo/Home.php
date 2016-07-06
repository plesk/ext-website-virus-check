<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.

class Modules_WebsiteVirusCheck_Promo_Home extends pm_Promo_AdminHome
{
    public function getTitle()
    {
        pm_Context::init('website-virus-check');
        return $this->lmsg('virustotalPromoTitle');
    }
    public function getText()
    {
        pm_Context::init('website-virus-check');

        $report = Modules_WebsiteVirusCheck_Helper::getDomainsReport();

        $total_domains = $report['total'];
        $last_scan = pm_Settings::get('last_scan');

        if ($last_scan) {
            $text = $this->lmsg('totalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        } else {
            $text = $this->lmsg('scanningWasNotPerformedYet');
        }

        if (count($report['bad']) > 0) {
            $text = $this->lmsg('totalReports') . count($report['bad']) . $this->lmsg('ofTotalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        }

        return $text;
    }
    public function getButtonText()
    {
        pm_Context::init('website-virus-check');
        return $this->lmsg('virustotalPromoButtonTitle');
    }
    public function getButtonUrl()
    {
        pm_Context::init('website-virus-check');
        return pm_Context::getBaseUrl();
    }
    public function getIconUrl()
    {
        pm_Context::init('website-virus-check');
        return pm_Context::getBaseUrl() . '/images/bug.png';
    }
}