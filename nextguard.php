<?php

defined('_JEXEC') || die;

use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Factory;
use Joomla\CMS\Http\HttpFactory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\Version;

/**
 * NextGuard Security Scanner — Joomla System Plugin
 *
 * Syncs installed extensions to NextGuard CVE monitoring on cron.
 * Uses Device Authorization Flow: API key → short code → device token stored in plugin params.
 *
 * @since 1.1.0
 */
class PlgSystemNextguard extends CMSPlugin
{
    protected $autoloadLanguage = true;

    /**
     * Returns the effective signing/auth key: device token if present, else legacy api_key.
     */
    private function effectiveKey(): string
    {
        $token = trim((string) $this->params->get('token', ''));
        if (!empty($token)) return $token;
        return trim((string) $this->params->get('api_key', ''));
    }

    /**
     * Runs on Joomla cron / scheduled task trigger.
     * In Joomla 3/4 this can be triggered via com_cron (Joomla 4.1+) or a
     * simple cron URL: index.php?option=com_ajax&plugin=nextguard&group=system
     */
    public function onAjaxNextguard(): void
    {
        // Also handle Device Auth Flow AJAX actions
        $task = Factory::getApplication()->input->get('ng_task', '', 'string');
        if ($task === 'request_code') {
            $this->ajaxRequestCode();
            return;
        }
        if ($task === 'poll_status') {
            $this->ajaxPollStatus();
            return;
        }

        $this->doSync();
    }

    /**
     * Also try to sync once per day using the after-route event if no cron.
     */
    public function onAfterRoute(): void
    {
        $app = Factory::getApplication();
        if ($app->isClient('site')) return;   // only in admin

        $lastSync = (int) $this->params->get('last_sync', 0);
        if ((time() - $lastSync) < 86400) return;

        $this->doSync();
    }

    // ── Device Authorization Flow ────────────────────────────────────────────

    /**
     * Security gate for the device-auth handlers.
     *
     * These run through the PUBLIC com_ajax endpoint and write the API key /
     * device token / project ID to the plugin params. Without this check an
     * unauthenticated visitor could overwrite the site's credentials and bind it
     * to an attacker-controlled NextGuard project (info disclosure of the
     * installed-extension inventory + integration hijack). Restrict to logged-in
     * Joomla administrators.
     */
    private function requireAdmin(): bool
    {
        $user = Factory::getApplication()->getIdentity();
        return $user && !$user->guest && $user->authorise('core.admin');
    }

    /**
     * AJAX handler: request an activation code from NextGuard.
     * Called via: index.php?option=com_ajax&plugin=nextguard&group=system&ng_task=request_code&api_key=...
     */
    private function ajaxRequestCode(): void
    {
        $app    = Factory::getApplication();

        if (!$this->requireAdmin()) {
            echo json_encode(['success' => false, 'message' => 'Unauthorized']);
            $app->close(); return;
        }

        $apiKey = trim($app->input->get('api_key', '', 'string'));

        if (empty($apiKey)) {
            echo json_encode(['success' => false, 'message' => 'API key is required.']);
            $app->close(); return;
        }
        if (strpos($apiKey, 'vs_pk_') !== 0) {
            echo json_encode(['success' => false, 'message' => 'Invalid API key. Keys must start with vs_pk_']);
            $app->close(); return;
        }

        // Anonymous Live Scan keys (vs_pk_anon_) skip the Device Authorization
        // Flow: there is no account to approve a code in. We persist the key,
        // sync immediately — the server binds the data to the ephemeral project
        // behind the key and returns the teaser preview — and report success so
        // the admin page can render the vulnerability table.
        if (strpos($apiKey, 'vs_pk_anon_') === 0) {
            $this->params->set('api_key',       $apiKey);
            $this->params->set('token',         '');
            $this->params->set('project_id',    '');
            $this->params->set('project_name',  '');
            $this->saveParams();

            $this->doSync();

            echo json_encode([
                'success' => true,
                'anon'    => true,
                'message' => 'Free scan complete — see the results below.',
            ]);
            $app->close(); return;
        }

        $http = HttpFactory::getHttp();
        try {
            $response = $http->post(
                (getenv('NEXTGUARD_API_BASE') ?: 'https://nextguardhq.com') . '/api/v1/auth/activate',
                '{}',
                ['Content-Type' => 'application/json', 'X-API-Key' => $apiKey],
                15
            );
            $data = json_decode($response->body, true);
            $code = $data['code'] ?? '';
            if (empty($code)) {
                echo json_encode(['success' => false, 'message' => 'Failed to get activation code. Check your API key.']);
                $app->close(); return;
            }

            // Persist API key and pending code in plugin params
            $this->params->set('api_key',              $apiKey);
            $this->params->set('activation_code',      $code);
            $this->params->set('activation_expires',   time() + ($data['expiresIn'] ?? 900));
            $this->saveParams();

            echo json_encode(['success' => true, 'code' => $code, 'expiresIn' => $data['expiresIn'] ?? 900]);
        } catch (\Exception $e) {
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        $app->close();
    }

    /**
     * AJAX handler: poll activation status.
     * Called via: index.php?option=com_ajax&plugin=nextguard&group=system&ng_task=poll_status
     */
    private function ajaxPollStatus(): void
    {
        $app     = Factory::getApplication();

        if (!$this->requireAdmin()) {
            echo json_encode(['success' => false, 'message' => 'Unauthorized']);
            $app->close(); return;
        }

        $code    = (string) $this->params->get('activation_code', '');
        $expires = (int) $this->params->get('activation_expires', 0);

        if (empty($code) || time() > $expires) {
            echo json_encode(['success' => true, 'status' => 'expired']);
            $app->close(); return;
        }

        $http = HttpFactory::getHttp();
        try {
            $response = $http->get(
                (getenv('NEXTGUARD_API_BASE') ?: 'https://nextguardhq.com') . '/api/v1/auth/activate?code=' . urlencode($code),
                [],
                10
            );
            $data   = json_decode($response->body, true);
            $status = $data['status'] ?? 'unknown';

            if ($status === 'authorized') {
                $token        = $data['token']       ?? '';
                $projectId    = $data['projectId']   ?? '';
                $projectName  = $data['projectName'] ?? '';

                $this->params->set('token',        $token);
                $this->params->set('project_id',   $projectId);
                $this->params->set('project_name', $projectName);
                // Clear pending code
                $this->params->set('activation_code',    '');
                $this->params->set('activation_expires', 0);
                $this->saveParams();
            }

            echo json_encode(['success' => true, 'status' => $status,
                'projectName' => $data['projectName'] ?? '', 'projectId' => $data['projectId'] ?? '']);
        } catch (\Exception $e) {
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        $app->close();
    }

    // ── Sync ─────────────────────────────────────────────────────────────────

    private function doSync(): void
    {
        $authKey   = $this->effectiveKey();
        $projectId = trim((string) $this->params->get('project_id', ''));
        $isAnon    = strpos($authKey, 'vs_pk_anon_') === 0;

        // Account keys require a bound project; anonymous keys do not (the server
        // binds the data to the ephemeral project behind the key).
        if (empty($authKey)) return;
        if (!$isAnon && empty($projectId)) return;

        $db    = $this->getDatabase();
        $query = $db->getQuery(true)
            ->select(['name', 'type', 'element', 'manifest_cache', 'enabled'])
            ->from($db->quoteName('#__extensions'))
            ->where($db->quoteName('type') . ' IN (' .
                $db->quote('component') . ',' .
                $db->quote('module') . ',' .
                $db->quote('plugin') . ',' .
                $db->quote('template') . ',' .
                $db->quote('library') .
            ')');

        $db->setQuery($query);
        $rows = $db->loadObjectList() ?: [];

        $components = [];
        foreach ($rows as $row) {
            $manifest = json_decode($row->manifest_cache, true) ?: [];
            $components[] = [
                'name'    => $row->name,
                'slug'    => $row->element,
                'version' => $manifest['version'] ?? 'unknown',
                'type'    => $row->type,
                'active'  => (bool) $row->enabled,
            ];
        }

        $jVersion = (new Version())->getShortVersion();
        $payload  = json_encode([
            'projectId'  => $projectId,
            'cmsType'    => 'joomla',
            'cmsVersion' => $jVersion,
            'phpVersion' => PHP_VERSION,
            'siteUrl'    => Uri::root(),
            'components' => $components,
        ]);

        try {
            // HMAC-SHA256 request signing — sign with device token (or legacy api_key)
            $timestamp   = time();
            $urlPath     = '/api/v1/cms/sync';
            $bodyHash    = hash('sha256', $payload);
            $sigPayload  = "{$timestamp}\nPOST\n{$urlPath}\n{$bodyHash}";
            $signature   = 'sha256=' . hash_hmac('sha256', $sigPayload, $authKey);

            $http     = HttpFactory::getHttp();
            $response = $http->post((getenv('NEXTGUARD_API_BASE') ?: 'https://nextguardhq.com') . '/api/v1/cms/sync', $payload, [
                'Content-Type'   => 'application/json',
                'X-API-Key'      => $authKey,
                'X-NG-Timestamp' => (string) $timestamp,
                'X-NG-Signature' => $signature,
            ], 45);

            $this->params->set('last_sync', time());

            // Capture the teaser preview (anonymous keys return it) so the admin
            // page can render the vulnerability table + register CTA, mirroring
            // the WordPress and Drupal plugins.
            $data = json_decode($response->body, true);
            if ($isAnon && is_array($data) && isset($data['preview'])) {
                $this->params->set('last_preview',     json_encode($data['preview']));
                $this->params->set('register_url',     $data['registerUrl'] ?? 'https://nextguardhq.com/register');
                $this->params->set('syncs_remaining',  isset($data['syncsRemaining']) ? (int) $data['syncsRemaining'] : '');
                $this->params->set('max_syncs',        isset($data['maxSyncs']) ? (int) $data['maxSyncs'] : '');
                $this->params->set('last_scan',        !empty($data['scannedAt']) ? $data['scannedAt'] : date('c'));
                if (!empty($data['plans']) && is_array($data['plans'])) {
                    $this->params->set('plan_links', json_encode($data['plans']));
                }
            }

            $this->saveParams();
        } catch (\Exception $e) {
            Factory::getApplication()->enqueueMessage('NextGuard sync error: ' . $e->getMessage(), 'error');
        }
    }

    /**
     * Loads the live plan catalog from the dashboard (Free/Monitoring/Starter),
     * cached for an hour in the Joomla cache. Falls back to a static set if the
     * endpoint is unreachable. Single source of truth shared with the website
     * pricing and the other plugins.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function fetchPlans(): array
    {
        $base   = rtrim(getenv('NEXTGUARD_API_BASE') ?: 'https://nextguardhq.com', '/');
        $lang   = Factory::getApplication()->getLanguage()->getTag() ?: 'en-GB';
        $locale = str_replace('-', '_', $lang);
        $cacheId = 'plans_' . substr(md5($base . '|' . $locale), 0, 12);

        $cache = Factory::getCache('plg_system_nextguard', '');
        $cache->setCaching(true);
        $cache->setLifeTime(60); // minutes
        $cached = $cache->get($cacheId);
        if (is_array($cached) && !empty($cached)) {
            return $cached;
        }

        try {
            $http = HttpFactory::getHttp();
            $url  = $base . '/api/public/plans?keys=free,monitoring,starter&locale=' . rawurlencode($locale);
            $resp = $http->get($url, ['ngrok-skip-browser-warning' => '1'], 8);
            if ((int) $resp->code === 200) {
                $data = json_decode($resp->body, true);
                if (is_array($data) && !empty($data['plans']) && is_array($data['plans'])) {
                    $cache->store($data['plans'], $cacheId);
                    return $data['plans'];
                }
            }
        } catch (\Exception $e) {
            // Fall through to the static fallback below.
        }

        // Fallback (endpoint unreachable) — static set, still localized.
        return [
            [
                'key' => 'free', 'name' => Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_FREE'), 'priceDisplay' => '$0', 'period' => '',
                'href' => $base . '/register', 'cta' => Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_FREE_CTA'), 'highlighted' => false,
                'features' => [
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_FREE_F1'),
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_FREE_F2'),
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_FREE_F3'),
                ],
            ],
            [
                'key' => 'monitoring', 'name' => Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_MONITORING'), 'priceDisplay' => '$3', 'period' => '/mo',
                'href' => $base . '/checkout/monitoring', 'cta' => Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_MONITORING_CTA'), 'highlighted' => true,
                'features' => [
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_MONITORING_F1'),
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_MONITORING_F2'),
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_MONITORING_F3'),
                ],
            ],
            [
                'key' => 'starter', 'name' => Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_STARTER'), 'priceDisplay' => '$7', 'period' => '/mo',
                'href' => $base . '/checkout/starter', 'cta' => Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_STARTER_CTA'), 'highlighted' => false,
                'features' => [
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_STARTER_F1'),
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_STARTER_F2'),
                    Text::_('PLG_SYSTEM_NEXTGUARD_PLAN_STARTER_F3'),
                ],
            ],
        ];
    }

    /**
     * Persist plugin params back to #__extensions.
     */
    private function saveParams(): void
    {
        $db    = $this->getDatabase();
        $query = $db->getQuery(true)
            ->update($db->quoteName('#__extensions'))
            ->set($db->quoteName('params') . ' = ' . $db->quote($this->params->toString()))
            ->where($db->quoteName('element') . ' = ' . $db->quote('nextguard'))
            ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'));
        $db->setQuery($query)->execute();
    }
}
