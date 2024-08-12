-- Usage of different Privacy Sandbox (PS) features by Top 10K publishers
-- Example: publisher.com: {“runAdAuction”: 10} [“runAdAuction” is a PS feature column and 10 is #TPs calling “runAdAuction” on publisher.com]

-- Extracting third-parties observed using PS APIs on a publisher
CREATE TEMP FUNCTION jsonObjectKeys(input STRING)
RETURNS ARRAY<STRING>
LANGUAGE js AS """
  if (!input) {
    return [];
  }
  return Object.keys(JSON.parse(input));
""";

-- Extracting PS APIs being called by a given third-party (passed as "key")
CREATE TEMP FUNCTION jsonObjectValues(input STRING, key STRING)
RETURNS ARRAY<STRING>
LANGUAGE js AS """
  if (!input) {
    return [];
  }
  const jsonObject = JSON.parse(input);
  const values = jsonObject[key] || [];
  
  function splitByDelimiters(value) {
    const delimiterRegex = new RegExp(',|, |\\n|\\u0000', 'g');
    return value.split(delimiterRegex).map(v => v.trim()).filter(v => v);
  }

  const result = [];
  values.forEach(value => {
    if (value.startsWith('accept-ch|')) {
      const parts = splitByDelimiters(value.replace('accept-ch|', ''));
      parts.forEach(part => {
        if (["UA", "Arch", "Bitness", "Full-Version-List", "Mobile", "Model", "Platform", "Platform-Version", "WoW64"].includes(part)) {
          result.push("Sec-CH-UA-" + part);
        } else {
          let formattedPart = part.split('-').map(segment => 
            segment.charAt(0).toUpperCase() + segment.slice(1).toLowerCase()
          ).join('-');
          formattedPart = formattedPart.replace('Ch', 'CH');
          formattedPart = formattedPart.replace('Ua', 'UA');
          formattedPart = formattedPart.replace('Wow64', 'WoW64');
          formattedPart = formattedPart.replace('Dpr', 'DPR');
          formattedPart = formattedPart.replace('Rtt', 'RTT');
          formattedPart = formattedPart.replace('Ect', 'ECT');
          result.push(formattedPart);
        }
      });
    } else {
      result.push(value);
    }
  });

  return result;
""";

WITH privacy_sandbox_features AS (
  SELECT
    NET.REG_DOMAIN(page) AS publisher,
    third_party_domain,
    CASE
      WHEN api LIKE '%opics%|%' THEN
        REPLACE(SUBSTR(api, 0, STRPOS(api, '|') - 1) || '-' || SPLIT(api, '|')[SAFE_OFFSET(1)], '|', '-')
      WHEN api LIKE 'attribution-reporting-register-source%' THEN
        SPLIT(api, '|')[OFFSET(0)]
      ELSE
        api
    END AS feature
  FROM `httparchive.all.pages`,
  UNNEST(jsonObjectKeys(JSON_QUERY(custom_metrics, '$.privacy-sandbox.privacySandBoxAPIUsage'))) AS third_party_domain,
  UNNEST(jsonObjectValues(JSON_QUERY(custom_metrics, '$.privacy-sandbox.privacySandBoxAPIUsage'), third_party_domain)) AS api
  WHERE
      date = '2024-06-01' AND
      client = 'desktop' AND
      is_root_page = TRUE AND
      rank <= 10000
),

grouped_features AS (
  SELECT
    publisher,
    feature,
    COUNT(DISTINCT third_party_domain) AS third_party_count
  FROM privacy_sandbox_features
  GROUP BY publisher, feature
)
SELECT
  publisher,
  SUM(IF(feature = 'runAdAuction', third_party_count, 0)) AS runAdAuction,
  SUM(IF(feature = 'navigator.userAgentData.getHighEntropyValues', third_party_count, 0)) AS navigator_userAgentData_getHighEntropyValues,
  SUM(IF(feature = 'fencedFrameJs', third_party_count, 0)) AS fencedFrameJs,
  SUM(IF(feature = 'attribution-reporting-eligible', third_party_count, 0)) AS attribution_reporting_eligible,
  SUM(IF(feature = 'attribution-reporting-register-source', third_party_count, 0)) AS attribution_reporting_register_source,
  SUM(IF(feature = 'navigator.credentials.get', third_party_count, 0)) AS navigator_credentials_get,
  SUM(IF(feature = 'IdentityProvider.getUserInfo', third_party_count, 0)) AS IdentityProvider_getUserInfo,
  SUM(IF(feature = 'IdentityProvider.close', third_party_count, 0)) AS IdentityProvider_close,
  SUM(IF(feature = 'navigator.login.setStatus', third_party_count, 0)) AS navigator_login_setStatus,
  SUM(IF(feature = 'fencedFrameJs', third_party_count, 0)) AS fencedFrameJs,
  SUM(IF(feature = 'FencedFrameConfig.setSharedStorageContext', third_party_count, 0)) AS FencedFrameConfig_setSharedStorageContext,
  SUM(IF(feature = 'window.fence.getNestedConfigs', third_party_count, 0)) AS window_fence_getNestedConfigs,
  SUM(IF(feature = 'window.fence.reportEvent', third_party_count, 0)) AS window_fence_reportEvent,
  SUM(IF(feature = 'window.fence.setReportEventDataForAutomaticBeacons', third_party_count, 0)) AS window_fence_setReportEventDataForAutomaticBeacons,
  SUM(IF(feature = 'fenced-frame', third_party_count, 0)) AS fenced_frame,
  SUM(IF(feature = 'document.interestCohort', third_party_count, 0)) AS document_interestCohort,
  SUM(IF(feature = 'privateAggregation.contributeToHistogram', third_party_count, 0)) AS privateAggregation_contributeToHistogram,
  SUM(IF(feature = 'privateAggregation.contributeToHistogramOnEvent', third_party_count, 0)) AS privateAggregation_contributeToHistogramOnEvent,
  SUM(IF(feature = 'privateAggregation.enableDebugMode', third_party_count, 0)) AS privateAggregation_enableDebugMode,
  SUM(IF(feature = 'document.hasPrivateToken', third_party_count, 0)) AS document_hasPrivateToken,
  SUM(IF(feature = 'document.hasRedemptionRecord', third_party_count, 0)) AS document_hasRedemptionRecord,
  SUM(IF(feature = 'sec-private-state-token', third_party_count, 0)) AS sec_private_state_token,
  SUM(IF(feature = 'sec-redemption-record', third_party_count, 0)) AS sec_redemption_record,
  SUM(IF(feature = 'joinAdInterestGroup', third_party_count, 0)) AS joinAdInterestGroup,
  SUM(IF(feature = 'leaveAdInterestGroup', third_party_count, 0)) AS leaveAdInterestGroup,
  SUM(IF(feature = 'updateAdInterestGroups', third_party_count, 0)) AS updateAdInterestGroups,
  SUM(IF(feature = 'clearOriginJoinedAdInterestGroups', third_party_count, 0)) AS clearOriginJoinedAdInterestGroups,
  SUM(IF(feature = 'runAdAuction', third_party_count, 0)) AS runAdAuction,
  SUM(IF(feature = 'generateBid', third_party_count, 0)) AS generateBid,
  SUM(IF(feature = 'scoreAd', third_party_count, 0)) AS scoreAd,
  SUM(IF(feature = 'reportWin', third_party_count, 0)) AS reportWin,
  SUM(IF(feature = 'reportResult', third_party_count, 0)) AS reportResult,
  SUM(IF(feature = 'window.sharedStorage.append', third_party_count, 0)) AS window_sharedStorage_append,
  SUM(IF(feature = 'window.sharedStorage.clear', third_party_count, 0)) AS window_sharedStorage_clear,
  SUM(IF(feature = 'window.sharedStorage.delete', third_party_count, 0)) AS window_sharedStorage_delete,
  SUM(IF(feature = 'window.sharedStorage.set', third_party_count, 0)) AS window_sharedStorage_set,
  SUM(IF(feature = 'window.sharedStorage.run', third_party_count, 0)) AS window_sharedStorage_run,
  SUM(IF(feature = 'window.sharedStorage.selectURL', third_party_count, 0)) AS window_sharedStorage_selectURL,
  SUM(IF(feature = 'window.sharedStorage.worklet.addModule', third_party_count, 0)) AS window_sharedStorage_worklet_addModule,
  SUM(IF(feature = 'document.hasStorageAccess', third_party_count, 0)) AS document_hasStorageAccess,
  SUM(IF(feature = 'document.hasUnpartitionedCookieAccess', third_party_count, 0)) AS document_hasUnpartitionedCookieAccess,
  SUM(IF(feature = 'document.requestStorageAccess', third_party_count, 0)) AS document_requestStorageAccess,
  SUM(IF(feature = 'document.requestStorageAccessFor', third_party_count, 0)) AS document_requestStorageAccessFor,
  SUM(IF(feature = 'document.browsingTopics-false', third_party_count, 0)) AS document_browsingTopics_false,
  SUM(IF(feature = 'document.browsingTopics-true', third_party_count, 0)) AS document_browsingTopics_true,
  SUM(IF(feature = 'sec-browsing-topics-false', third_party_count, 0)) AS sec_browsing_topics_false,
  SUM(IF(feature = 'sec-browsing-topics-true', third_party_count, 0)) AS sec_browsing_topics_true,
  SUM(IF(feature = 'navigator.userAgentData.getHighEntropyValues', third_party_count, 0)) AS navigator_userAgentData_getHighEntropyValues,
  SUM(IF(feature = 'Sec-CH-DPR', third_party_count, 0)) AS Sec_CH_DPR,
  SUM(IF(feature = 'Sec-CH-Device-Memory', third_party_count, 0)) AS Sec_CH_Device_Memory,
  SUM(IF(feature = 'Sec-CH-Downlink', third_party_count, 0)) AS Sec_CH_Downlink,
  SUM(IF(feature = 'Sec-CH-ECT', third_party_count, 0)) AS Sec_CH_ECT,
  SUM(IF(feature = 'Sec-CH-Forced-Colors', third_party_count, 0)) AS Sec_CH_Forced_Colors,
  SUM(IF(feature = 'Sec-CH-Prefers-Color-Scheme', third_party_count, 0)) AS Sec_CH_Prefers_Color_Scheme,
  SUM(IF(feature = 'Sec-CH-Prefers-Contrast', third_party_count, 0)) AS Sec_CH_Prefers_Contrast,
  SUM(IF(feature = 'Sec-CH-Prefers-Reduced-Data', third_party_count, 0)) AS Sec_CH_Prefers_Reduced_Data,
  SUM(IF(feature = 'Sec-CH-Prefers-Reduced-Motion', third_party_count, 0)) AS Sec_CH_Prefers_Reduced_Motion,
  SUM(IF(feature = 'Sec-CH-Prefers-Reduced-Transparency', third_party_count, 0)) AS Sec_CH_Prefers_Reduced_Transparency,
  SUM(IF(feature = 'Sec-CH-RTT', third_party_count, 0)) AS Sec_CH_RTT,
  SUM(IF(feature = 'Sec-CH-Save-Data', third_party_count, 0)) AS Sec_CH_Save_Data,
  SUM(IF(feature = 'Sec-CH-UA', third_party_count, 0)) AS Sec_CH_UA,
  SUM(IF(feature = 'Sec-CH-UA-Arch', third_party_count, 0)) AS Sec_CH_UA_Arch,
  SUM(IF(feature = 'Sec-CH-UA-Architecture', third_party_count, 0)) AS Sec_CH_UA_Architecture,
  SUM(IF(feature = 'Sec-CH-UA-Bitness', third_party_count, 0)) AS Sec_CH_UA_Bitness,
  SUM(IF(feature = 'Sec-CH-UA-Form-Factor', third_party_count, 0)) AS Sec_CH_UA_Form_Factor,
  SUM(IF(feature = 'Sec-CH-UA-Form-Factors', third_party_count, 0)) AS Sec_CH_UA_Form_Factors,
  SUM(IF(feature = 'Sec-CH-UA-Full', third_party_count, 0)) AS Sec_CH_UA_Full,
  SUM(IF(feature = 'Sec-CH-UA-Full-Version', third_party_count, 0)) AS Sec_CH_UA_Full_Version,
  SUM(IF(feature = 'Sec-CH-UA-Full-Version-List', third_party_count, 0)) AS Sec_CH_UA_Full_Version_List,
  SUM(IF(feature = 'Sec-CH-UA-Mobile', third_party_count, 0)) AS Sec_CH_UA_Mobile,
  SUM(IF(feature = 'Sec-CH-UA-Model', third_party_count, 0)) AS Sec_CH_UA_Model,
  SUM(IF(feature = 'Sec-CH-UA-Platform', third_party_count, 0)) AS Sec_CH_UA_Platform,
  SUM(IF(feature = 'Sec-CH-UA-Platform-Version', third_party_count, 0)) AS Sec_CH_UA_Platform_Version,
  SUM(IF(feature = 'Sec-CH-UA-Platform-WoW64', third_party_count, 0)) AS Sec_CH_UA_Platform_WoW64,
  SUM(IF(feature = 'Sec-CH-UA-Platformuser-Agent', third_party_count, 0)) AS Sec_CH_UA_Platformuser_Agent,
  SUM(IF(feature = 'Sec-CH-UA-UA', third_party_count, 0)) AS Sec_CH_UA_UA,
  SUM(IF(feature = 'Sec-CH-UA-WoW64', third_party_count, 0)) AS Sec_CH_UA_WoW64,
  SUM(IF(feature = 'Sec-CH-Viewport-Height', third_party_count, 0)) AS Sec_CH_Viewport_Height,
  SUM(IF(feature = 'Sec-CH-Viewport-Width', third_party_count, 0)) AS Sec_CH_Viewport_Width,
  SUM(IF(feature = 'Sec-CH-Width', third_party_count, 0)) AS Sec_CH_Width
FROM grouped_features
GROUP BY publisher
ORDER BY publisher;
