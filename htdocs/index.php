<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.

$moduleId = basename(dirname(__FILE__));

pm_Context::init($moduleId);

$application = new pm_Application();
$application->run();
