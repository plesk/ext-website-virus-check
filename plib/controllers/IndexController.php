<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.

class IndexController extends pm_Controller_Action
{
    public function init()
    {
        $this->_accessLevel = 'admin';
        
        parent::init();
        
        
        $this->view->pageTitle = $this->lmsg('pageTitle');
        
        $this->view->tabs = [
            [
                'title' => $this->lmsg('tabReports'),
                'action' => 'report',
            ],
            [
                'title' => $this->lmsg('tabSettings'),
                'action' => 'settings',
            ],
            [
                'title' => $this->lmsg('tabAbout'),
                'action' => 'about',
            ],
        ];
    }

    public function indexAction()
    {
        if (!pm_Settings::get('virustotal_enabled') || pm_Settings::get('apiKeyBecameInvalid')) {
            $this->_forward('settings');
            return;
        }

        $this->_forward('report');
    }

    public function reportAction()
    {
        if (!pm_Settings::get('virustotal_enabled')) {
            $this->_forward('settings');
            return;
        }

        if (pm_Settings::get('apiKeyBecameInvalid') && !$this->_status->hasMessage($this->lmsg('apiKeyBecameInvalid'))) {
            $this->_status->addError($this->lmsg('apiKeyBecameInvalid'));
        }
        
        $this->view->list = $this->_getDomainsReportList();
        $this->view->scan = [];
        
        if (class_exists('pm_LongTask_Manager')) { // Since Plesk 17.0
            $isRunning = pm_Settings::get('scan_lock');
            $action = $isRunning ? 'stop' : 'start';

            $this->view->scan[] = [
                'title' => $isRunning ? $this->lmsg('buttonStopScan') : $this->lmsg('buttonStartScan'),
                'description' => $isRunning ? $this->lmsg('buttonStopDesc') : $this->lmsg('buttonStartDesc'),
                'icon' => pm_Context::getBaseUrl() . "/images/{$action}.png",
                'link' => $this->view->getHelper('baseUrl')->moduleUrl(['action' => $action]),
            ];
            
        } else {
            $this->view->summary = $this->_getReportSummary();
        }
    }

    public function startAction()
    {
        $allDomains = Modules_WebsiteVirusCheck_Helper::getDomains();
        $selectedDomainIds = (array)$this->_getParam('ids');
        $selectedDomains = [];
        foreach ($allDomains as $domain) {
            if (in_array($domain->id, $selectedDomainIds)) {
                $selectedDomains[$domain->id] = $domain;
            }
        }

        $taskManager = new pm_LongTask_Manager();
        $scanTask = new Modules_WebsiteVirusCheck_Task_Scan();
        $scanTask->setParams(['selectedDomains' => $selectedDomains]);
        $taskManager->start($scanTask);

        for ($i = 1; $i < 5; $i++) { // wait for acquiring lock to keep UI consistent
            if (pm_Settings::get('scan_lock')) {
                break;
            }
            sleep(1);
        }

        $this->view->status->addInfo($this->lmsg('infoStartSuccess'));
        $this->_redirect(pm_Context::getBaseUrl());
    }

    public function stopAction()
    {
        $taskManager = new pm_LongTask_Manager();
        $taskManager->cancelAllTasks();

        pm_Settings::set('scan_lock', 0);

        $this->view->status->addInfo($this->lmsg('infoStopSuccess'));
        $this->_redirect(pm_Context::getBaseUrl());
    }

    public function reportDataAction()
    {
        $list = $this->_getDomainsReportList();
        // Json data from pm_View_List_Simple
        $this->_helper->json($list->fetchData());
    }
    
    public function settingsAction()
    {
        if (pm_Settings::get('apiKeyBecameInvalid') && !$this->_status->hasMessage($this->lmsg('apiKeyBecameInvalid'))) {
            $this->_status->addError($this->lmsg('apiKeyBecameInvalid'));
        }
        
        $this->view->help_tip = $this->lmsg('apikey_help');

        $form = new Modules_WebsiteVirusCheck_SettingsForm();

        $form->addElement('checkbox', 'virustotal_enabled', [
            'label' => $this->lmsg('virustotalEnabled'),
            'value' => pm_Settings::get('virustotal_enabled'),
        ]);

        $form->addElement('text', 'virustotal_api_key', [
            'label' => $this->lmsg('virustotalPublicApiKey'),
            'value' => pm_Settings::get('virustotal_api_key'),
            'required' => true,
            'validators' => [
                ['NotEmpty', true],
            ],
        ]);

        $form->addElement('checkbox', 'emailNotificationEnabled', [
            'label' => $this->lmsg('emailNotificationEnabled'),
            'value' => pm_Settings::get('emailNotificationEnabled'),
        ]);

        $form->addElement('checkbox', '_promo_admin_home', [
            'label' => $this->lmsg('adminHomeWidgetEnabled'),
            'value' => pm_Settings::get('_promo_admin_home'),
        ]);

        $form->addControlButtons([
            'cancelLink' => pm_Context::getModulesListUrl(),
        ]);

        if ($this->getRequest()->isPost() && $form->isValid($this->getRequest()->getPost())) {

            pm_Settings::set('apiKeyBecameInvalid', '');
            pm_Settings::set('virustotal_enabled', $form->getValue('virustotal_enabled'));
            pm_Settings::set('virustotal_api_key', $form->getValue('virustotal_api_key'));
            pm_Settings::set('emailNotificationEnabled', $form->getValue('emailNotificationEnabled'));
            pm_Settings::set('_promo_admin_home', $form->getValue('_promo_admin_home'));
            
            $this->_status->addMessage('info', $this->lmsg('settingsWasSuccessfullySaved'));
            $this->_helper->json(['redirect' => pm_Context::getBaseUrl()]);
        }

        $this->view->form = $form;
    }

    public function aboutAction()
    {
        if (pm_Settings::get('apiKeyBecameInvalid') && !$this->_status->hasMessage($this->lmsg('apiKeyBecameInvalid'))) {
            $this->_status->addError($this->lmsg('apiKeyBecameInvalid'));
        }
        
        $this->view->about = $this->lmsg('about');
        $this->view->feedback = $this->lmsg('feedback');
        $this->view->faq = $this->lmsg('faq');
        $this->view->question1 = $this->lmsg('question1');
        $this->view->question2 = $this->lmsg('question2');
        $this->view->question3 = $this->lmsg('question3');
    }
    
    private function _getReportSummary()
    {
        $report = Modules_WebsiteVirusCheck_Helper::getDomainsReport();
                
        $total_domains = $report['total'];
        $last_scan = pm_Settings::get('last_scan');

        if ($last_scan) {
            $text = $this->lmsg('totalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        } else {
            $text = $this->lmsg('scanningWasNotPerformedYet') . ' ' . $this->lmsg('youCanStartTaskAt');
        }
        
        if (count($report['bad']) > 0) {
            $text = $this->lmsg('totalReports') . count($report['bad']) . $this->lmsg('ofTotalDomains') . $total_domains . ', ' . $this->lmsg('lastScan') . $last_scan;
        }

        return $text;
    }
    
    private function _getDomainsReportList() 
    {
        $data = [];
        $report = Modules_WebsiteVirusCheck_Helper::getDomainsReport();
        foreach ($report['all'] as $domain) {
            $colScanDate = isset($domain->virustotal_scan_date) ? $domain->virustotal_scan_date : '';
            $colScanResult = pm_Locale::lmsg('domainInactiveOrCantbeResolvedInHostingIp');
            $colBadUrlsAndSamples = $domain->virustotal_bad_urls_and_samples;
            $colReportLink = '';
            $isDomainAvailable = $domain->isAvailable();
            if ($isDomainAvailable) {
                if (isset($domain->no_scanning_results)) {
                    $colScanResult = $domain->no_scanning_results;
                } else {
                    $colScanResult = $domain->virustotal_positives . ' / ' . $domain->virustotal_total;
                    $colReportLink = '<a rel="noopener noreferrer" target="_blank" href="' . $domain->virustotal_domain_info_url . '">' . $this->lmsg('virustotalReport') . '</a>';
                }
            }

            if (!$isDomainAvailable) {
                $stateImgSrc = pm_Context::getBaseUrl() . '/images/warning.png';
                $stateImgAlt = $this->lmsg('domainInactiveOrCantbeResolvedInHostingIp');
            } else if ($domain->enabled) {
                $stateImgSrc = pm_Context::getBaseUrl() . '/images/enabled.png';
                $stateImgAlt = $this->lmsg('scanningEnabled');  
                if ((int)$domain->virustotal_positives > 0 || $domain->virustotal_bad_urls_and_samples > 0) {
                    $stateImgSrc = pm_Context::getBaseUrl() . '/images/bad.png';
                    $stateImgAlt = $this->lmsg('badReport');
                }
            } else {
                $stateImgSrc = pm_Context::getBaseUrl() . '/images/disabled.png';
                $stateImgAlt = $this->lmsg('scanningDisabled');
            }

            $colScanningState = '<img src="' . $stateImgSrc . '" title="' . htmlspecialchars($stateImgAlt, ENT_QUOTES) . '">';
            $colDomain = '<a target="_blank" href="/admin/subscription/login/id/' . $domain->webspace_id . '?pageUrl=/web/overview/id/d:' . $domain->id . '">' . $domain->name . '</a>';
            $data[$domain->id] = [
                'column-1' => $colScanningState,
                'column-2' => $colDomain,
                'column-3' => $colScanDate,
                'column-4' => $colScanResult,
                'column-5' => $colBadUrlsAndSamples,
                'column-6' => $colReportLink,
            ];
        }
        
        if (!count($data) > 0) {
            return new pm_View_List_Simple($this->view, $this->_request);
        }
        
        $options = [
            'defaultSortField' => 'column-2',
            'defaultSortDirection' => pm_View_List_Simple::SORT_DIR_DOWN,
        ];
        $list = new pm_View_List_Simple($this->view, $this->_request, $options);
        $list->setData($data);
        $list->setColumns([
            pm_View_List_Simple::COLUMN_SELECTION,
            'column-1' => [
                'title' => $this->lmsg('scanningState'),
                'noEscape' => true,
                'searchable' => false,
                'sortable' => true,
            ],
            'column-2' => [
                'title' => $this->lmsg('domain'),
                'noEscape' => true,
                'searchable' => true,
                'sortable' => true,
            ],
            'column-3' => [
                'title' => $this->lmsg('scanDate'),
                'sortable' => true,
            ],
            'column-4' => [
                'title' => $this->lmsg('checkResult'),
                'sortable' => true,
            ],
            'column-5' => [
                'title' => $this->lmsg('badUrlsAndSamples'),
                'sortable' => true,
            ],
            'column-6' => [
                'title' => $this->lmsg('reportLink'),
                'noEscape' => true,
                'searchable' => false,
                'sortable' => false,
                
            ],
        ]);

        $listTools = [];
        if (class_exists('pm_LongTask_Manager')) { // Since Plesk 17.0
            $isRunning = pm_Settings::get('scan_lock');
            $action = $isRunning ? 'stop' : 'start';
            if ($action == 'start') {
                $listTools[] = [
                    'title' => $isRunning ? $this->lmsg('buttonStopScan') : $this->lmsg('buttonStartScan'),
                    'description' => $isRunning ? $this->lmsg('buttonStopDesc') : $this->lmsg('buttonStartSelectedDesc'),
                    'class' => "sb-{$action}",
                    'execGroupOperation' => $this->_helper->url($action),
                ];
            } else {
                $listTools[] = [
                    'title' => $isRunning ? $this->lmsg('buttonStopScan') : $this->lmsg('buttonStartScan'),
                    'description' => $isRunning ? $this->lmsg('buttonStopDesc') : $this->lmsg('buttonStartSelectedDesc'),
                    'class' => "sb-{$action}",
                    'link' => $this->view->getHelper('baseUrl')->moduleUrl(['action' => $action]),
                ];
            }
        }
        $listTools[] = [
            'title' => $this->lmsg('buttonEnable'),
            'description' => $this->lmsg('buttonEnableDesc'),
            'class' => 'sb-make-visible',
            'execGroupOperation' => $this->_helper->url('enable'),
        ];
        $listTools[] = [
            'title' => $this->lmsg('buttonDisable'),
            'description' => $this->lmsg('buttonDisableDesc'),
            'class' => 'sb-make-invisible',
            'execGroupOperation' => $this->_helper->url('disable'),
        ];

        $list->setTools($listTools);

        $list->setDataUrl(['action' => 'report-data']);
        return $list;
    }

    public function enableAction()
    {
        foreach ((array)$this->_getParam('ids') as $domainId) {
            $report = json_decode(pm_Settings::get('domain_id_' . $domainId), true);
            if ($report) {
                $report['domain']['enabled'] = true;
                pm_Settings::set('domain_id_' . $domainId, json_encode($report));
            }
        }
        $messages[] = ['status' => 'info', 'content' => $this->lmsg('buttonEnableSuccess')];
        $this->_helper->json(['status' => 'success', 'statusMessages' => $messages]);
    }

    public function disableAction()
    {
        foreach ((array)$this->_getParam('ids') as $domainId) {
            $report = json_decode(pm_Settings::get('domain_id_' . $domainId), true);
            if ($report) {
                $report['domain']['enabled'] = false;
                pm_Settings::set('domain_id_' . $domainId, json_encode($report));
            }
        }
        $messages[] = ['status' => 'info', 'content' => $this->lmsg('buttonDisableSuccess')];
        $this->_helper->json(['status' => 'success', 'statusMessages' => $messages]);
    }
}
