<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.
pm_Context::init('website-virus-check');

pm_Scheduler::getInstance()->removeAllTasks();

pm_Settings::clean();