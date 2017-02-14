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
        $taskManager = new pm_LongTask_Manager();
        $task1 = new Modules_WebsiteVirusCheck_Task_Scan();
        $taskManager->start($task1);

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
            $scan_date_column = isset($domain->virustotal_scan_date) ? $domain->virustotal_scan_date : '';
            if (isset($domain->no_scanning_results)) {
                $result_column = $domain->no_scanning_results;
                $report_link_column = '';
            } else {
                $result_column = $domain->virustotal_positives . ' / ' . $domain->virustotal_total;
                $report_link_column = '<a rel="noopener noreferrer" target="_blank" href="' . $domain->virustotal_domain_info_url . '">' .  $this->lmsg('virustotalReport') . '</a>';
            }

            $col_1 = '<a target="_blank" href="/admin/subscription/login/id/' . $domain->webspace_id . '?pageUrl=/web/overview/id/d:' . $domain->id . '">' . $domain->name . '</a>';
            if (!$domain->enabled) {
                $disabledImage = pm_Context::getBaseUrl() . '/images/disabled.png';
                $col_1 = '<img src="' . $disabledImage . '" alt="Scanning disabled" title=""> ' . $col_1;
            }

            $data[$domain->id] = [
                'column-1' => $col_1,
                'column-2' => $domain->getAvailable(),
                'column-3' => $scan_date_column,
                'column-4' => $result_column,
                'column-5' => $report_link_column,
            ];
        }
        
        if (!count($data) > 0) {
            return new pm_View_List_Simple($this->view, $this->_request);
        }
        
        $options = [
            'defaultSortField' => 'column-1',
            'defaultSortDirection' => pm_View_List_Simple::SORT_DIR_DOWN,
        ];
        $list = new pm_View_List_Simple($this->view, $this->_request, $options);
        $list->setData($data);
        $list->setColumns([
            pm_View_List_Simple::COLUMN_SELECTION,
            'column-1' => [
                'title' => $this->lmsg('domain'),
                'noEscape' => true,
                'searchable' => true,
                'sortable' => true,
            ],
            'column-2' => [
                'title' => $this->lmsg('availableForScanning'),
                'searchable' => false,
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
                'title' => $this->lmsg('reportLink'),
                'noEscape' => true,
                'searchable' => false,
                'sortable' => false,
                
            ],
        ]);

        $list->setTools([
            [
                'title' => $this->lmsg('buttonEnable'),
                'description' => $this->lmsg('buttonEnableDesc'),
                'class' => 'sb-make-visible',
                'execGroupOperation' => $this->_helper->url('enable'),
            ],
            [
                'title' => $this->lmsg('buttonDisable'),
                'description' => $this->lmsg('buttonDisableDesc'),
                'class' => 'sb-make-invisible',
                'execGroupOperation' => $this->_helper->url('disable'),
            ],
        ]);

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
