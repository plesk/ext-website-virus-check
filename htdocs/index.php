<?php
$moduleId = basename(dirname(__FILE__));

pm_Context::init($moduleId);

$application = new pm_Application();
$application->run();
