<?php

defined('_JEXEC') || die;

use Joomla\CMS\Form\FormField;
use Joomla\CMS\Language\Text;

require_once __DIR__ . '/../nextguard.php';

/**
 * Custom form field that renders the NextGuard admin panel inside the plugin
 * params fieldset: the vulnerability teaser table captured from the last
 * anonymous scan plus a live "create an account" plans panel loaded from the
 * dashboard.
 *
 * Mirrors the WordPress and Drupal plugin admin pages.
 */
class JFormFieldNextguardpanel extends FormField
{
    protected $type = 'Nextguardpanel';

    /**
     * The field is purely informational — render the panel as its input.
     */
    protected function getInput(): string
    {
        // The bound params live on the form object as the field's data source.
        $params = $this->form->getData();

        $previewRaw    = (string) $params->get('params.last_preview', '');
        $preview       = $previewRaw ? json_decode($previewRaw, true) : null;
        $registerUrl   = (string) ($params->get('params.register_url', '') ?: 'https://nextguardhq.com/register');
        $syncsLeft     = $params->get('params.syncs_remaining', '');
        $lastScan      = (string) $params->get('params.last_scan', '');
        $planLinksRaw  = (string) $params->get('params.plan_links', '');
        $planLinks     = $planLinksRaw ? json_decode($planLinksRaw, true) : [];

        return $this->renderPanel(
            is_array($preview) ? $preview : null,
            $registerUrl,
            $syncsLeft,
            $lastScan,
            is_array($planLinks) ? $planLinks : []
        );
    }

    /**
     * The label is suppressed — the panel renders full width.
     */
    protected function getLabel(): string
    {
        return '';
    }

    /**
     * Builds the teaser table + register CTA + live plans panel as HTML.
     */
    private function renderPanel(?array $preview, string $registerUrl, $syncsLeft, string $lastScan, array $planLinks): string
    {
        $sevColors = ['CRITICAL' => '#dc2626', 'HIGH' => '#ea580c', 'MEDIUM' => '#ca8a04', 'LOW' => '#65a30d'];
        $esc       = static fn($v) => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        $hasResults = is_array($preview) && !empty($preview['available'])
            && !empty($preview['summary']) && (int) ($preview['summary']['total'] ?? 0) > 0;

        $h = '<div style="display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start;margin-top:8px;">';

        // ── Left column: results teaser (or clean / empty state) ──
        $h .= '<div style="flex:1 1 520px;min-width:300px;">';

        if ($hasResults) {
            $s = $preview['summary'];
            $h .= '<h3 style="margin:0 0 4px;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_RESULTS_TITLE')) . '</h3>';
            $h .= '<p style="font-size:20px;font-weight:700;color:#dc2626;margin:0 0 4px;">' .
                $esc(Text::sprintf('PLG_SYSTEM_NEXTGUARD_VULNS_FOUND', (int) $s['total'])) . '</p>';
            if ($lastScan) {
                $h .= '<p style="margin:0 0 8px;color:#6b7280;font-size:12px;">&#128337; ' .
                    $esc(Text::sprintf('PLG_SYSTEM_NEXTGUARD_LAST_SCAN', $lastScan)) . '</p>';
            }
            $h .= '<p style="margin:0 0 12px;font-family:monospace;font-size:13px;">' .
                '<span style="color:#dc2626;">' . (int) ($s['critical'] ?? 0) . ' CRITICAL</span> &middot; ' .
                '<span style="color:#ea580c;">' . (int) ($s['high'] ?? 0) . ' HIGH</span> &middot; ' .
                '<span style="color:#ca8a04;">' . (int) ($s['medium'] ?? 0) . ' MEDIUM</span> &middot; ' .
                '<span style="color:#65a30d;">' . (int) ($s['low'] ?? 0) . ' LOW</span></p>';

            $h .= '<table style="width:100%;border-collapse:collapse;"><thead><tr>' .
                '<th style="text-align:left;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_COL_SEVERITY')) . '</th>' .
                '<th style="text-align:left;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_COL_COMPONENT')) . '</th>' .
                '<th style="text-align:left;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_COL_INSTALLED')) . '</th>' .
                '<th style="text-align:left;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_COL_VULN')) . '</th>' .
                '<th style="text-align:left;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_COL_FIXED')) . '</th>' .
                '</tr></thead><tbody>';
            foreach (($preview['shown'] ?? []) as $v) {
                $sev = strtoupper($v['severity'] ?? '—');
                $col = $sevColors[$sev] ?? '#65a30d';
                $h .= '<tr>' .
                    '<td><strong style="font-size:11px;color:' . $col . ';">' . $esc($sev) . '</strong></td>' .
                    '<td><strong>' . $esc($v['componentName'] ?? $v['component'] ?? '—') . '</strong></td>' .
                    '<td><code>' . $esc($v['installedVersion'] ?? '—') . '</code></td>' .
                    '<td>' . $esc($v['title'] ?? ($v['cveId'] ?? '—')) . '</td>' .
                    '<td>' . $esc($v['fixedIn'] ?? '—') . '</td></tr>';
            }
            $hidden = (int) ($preview['hidden'] ?? 0);
            for ($i = 0; $i < min(3, $hidden); $i++) {
                $h .= '<tr style="filter:blur(3px);user-select:none;"><td><strong style="font-size:11px;color:#dc2626;">HIGH</strong></td>' .
                    '<td>&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;</td><td>&#9608;.&#9608;.&#9608;</td><td>&#9608;&#9608;&#9608;&#9608; &#9608;&#9608;&#9608; &#9608;&#9608;&#9608;&#9608;&#9608;</td><td>&#9608;.&#9608;.&#9608;</td></tr>';
            }
            $h .= '</tbody></table>';
            if ($hidden > 0) {
                $h .= '<p style="font-weight:600;color:#b45309;margin:12px 0 0;">' .
                    $esc(Text::sprintf('PLG_SYSTEM_NEXTGUARD_HIDDEN', $hidden)) . '</p>';
            }
            $h .= '<p style="margin:14px 0 0;"><a href="' . $esc($registerUrl) . '" target="_blank" class="btn btn-primary">' .
                $esc(Text::_('PLG_SYSTEM_NEXTGUARD_REGISTER_CTA')) . '</a></p>';
            if ($syncsLeft !== null && $syncsLeft !== '') {
                $h .= '<p style="margin:10px 0 0;color:#6b7280;font-size:12px;">&#9432; ' .
                    $esc(Text::sprintf('PLG_SYSTEM_NEXTGUARD_SYNCS_LEFT', (int) $syncsLeft)) . '</p>';
            }
        } elseif (is_array($preview) && !empty($preview['available'])) {
            $h .= '<div class="alert alert-success">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_NO_VULNS')) . '</div>';
        } else {
            $h .= '<p style="color:#6b7280;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_NO_SCAN_YET')) . '</p>';
        }
        $h .= '</div>';

        // ── Right column: live plans panel ──
        $h .= '<div style="flex:0 0 320px;min-width:280px;background:#0f172a;border-radius:8px;padding:18px;color:#e2e8f0;">';
        $h .= '<h3 style="margin:0 0 6px;color:#fff;font-size:16px;">' . $esc(Text::_('PLG_SYSTEM_NEXTGUARD_PLANS_TITLE')) . '</h3>';
        $h .= '<p style="margin:0 0 14px;color:#94a3b8;font-size:12.5px;line-height:1.6;">' .
            $esc(Text::_('PLG_SYSTEM_NEXTGUARD_PLANS_INTRO')) . '</p>';

        foreach (PlgSystemNextguard::fetchPlans() as $p) {
            $key = $p['key'] ?? '';
            // Origin-aware upgrade link from the sync response wins, if present.
            $href = (is_array($planLinks) && !empty($planLinks[$key])) ? $planLinks[$key] : ($p['href'] ?? '#');
            $hot   = !empty($p['highlighted']);
            $price = ($p['priceDisplay'] ?? ($p['price'] ?? '')) . ($p['period'] ?? '');
            $h .= '<div style="border:1px solid ' . ($hot ? '#0ea5e9' : '#1e293b') . ';border-radius:6px;padding:12px;margin:0 0 10px;background:#111827;">';
            $h .= '<div style="display:flex;justify-content:space-between;align-items:baseline;margin:0 0 8px;">' .
                '<strong style="font-size:14px;color:#fff;">' . $esc($p['name'] ?? '') . '</strong>' .
                '<span style="font-size:13px;color:#38bdf8;font-weight:700;">' . $esc($price) . '</span></div>';
            $h .= '<ul style="list-style:none;margin:0 0 10px;padding:0;font-size:12px;color:#cbd5e1;line-height:1.5;">';
            foreach (($p['features'] ?? []) as $f) {
                $h .= '<li style="margin:0 0 4px;"><span style="color:#22c55e;">&#10003;</span> ' . $esc($f) . '</li>';
            }
            $h .= '</ul>';
            $h .= '<a href="' . $esc($href) . '" target="_blank" class="btn' . ($hot ? ' btn-primary' : ' btn-secondary') . '" style="display:block;text-align:center;">' .
                $esc($p['cta'] ?? '') . '</a>';
            $h .= '</div>';
        }
        $h .= '</div>';

        $h .= '</div>';
        return $h;
    }
}
