<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.

class Modules_WebsiteVirusCheck_Task_Scan extends pm_LongTask_Task // Since Plesk 17.0
{
    public $trackProgress = true;

    public function run()
    {
        Modules_WebsiteVirusCheck_Helper::check(); // scan_lock is acquired inside check()
    }

    public function statusMessage()
    {
        switch ($this->getStatus()) {
            case static::STATUS_RUNNING:
                return pm_Locale::lmsg('scanTaskRunning');
            case static::STATUS_DONE:
                return pm_Locale::lmsg('scanTaskDone');
        }
        return '';
    }

    public function onDone()
    {
        pm_Settings::set('scan_lock', 0); // Just in case some troubles inside check()
    }
}