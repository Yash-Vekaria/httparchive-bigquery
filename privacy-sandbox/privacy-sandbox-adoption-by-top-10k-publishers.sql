-- Usage of different Privacy Sandbox (PS) features by Top 10K publishers
-- Example: publisher.com: {“runAdAuction”: 10} [“runAdAuction” is a PS feature column and 10 is #TPs calling “runAdAuction” on publisher.com]
-- This query will process 63.29 TB when run.
WITH pages AS (
  SELECT
    NET.REG_DOMAIN(page) AS publisher,
    JSON_EXTRACT(custom_metrics, '$._privacy-sandbox.privacySandBoxAPIUsage') AS api_usage
  FROM `httparchive.all.pages`
  WHERE
    date = '2024-06-01' AND
    client = 'desktop' AND
    is_root_page = TRUE AND
    rank <= 10000
),
exploded_features AS (
  SELECT
    publisher,
    REGEXP_EXTRACT(feature, r'"([^"]+)":') AS third_party_domain,
    TRIM(value) AS feature_values
  FROM
    pages,
    UNNEST(REGEXP_EXTRACT_ALL(TO_JSON_STRING(api_usage), r'"([^"]+)":\s*\[([^\]]*)\]')) AS feature,
    UNNEST(SPLIT(REGEXP_EXTRACT(feature, r'\[([^\]]*)\]'), ',')) AS value
),
cleaned_features AS (
  SELECT
    publisher,
    third_party_domain,
    CASE
      WHEN feature_values LIKE 'accept-ch|%' THEN
        SPLIT(SUBSTR(feature_values, STRPOS(feature_values, '|') + 1), ',')
      WHEN feature_values LIKE '%opics|%' THEN
        [REPLACE(SUBSTR(feature_values, 0, STRPOS(feature_values, '|') - 1) || '-' || SPLIT(feature_values, '|')[SAFE_OFFSET(1)], '|', '-')]
      WHEN feature_values LIKE 'attribution-reporting-register-source%' THEN
        [SPLIT(feature_values, '|')[OFFSET(0)]]
      ELSE
        [feature_values]
    END AS features
  FROM exploded_features
),
distinct_features AS (
  SELECT
    publisher,
    feature,
    COUNT(DISTINCT third_party_domain) AS tp_count
  FROM cleaned_features,
  UNNEST(features) AS feature
  GROUP BY publisher, feature
), 
pivoted_data AS (
  SELECT
    publisher,
    MAX(IF(feature = 'runAdAuction', tp_count, 0)) AS runAdAuction,
    MAX(IF(feature = 'navigator.userAgentData.getHighEntropyValues', tp_count, 0)) AS navigator_userAgentData_getHighEntropyValues,
    MAX(IF(feature = 'fencedFrameJs', tp_count, 0)) AS fencedFrameJs,
    MAX(IF(feature = 'attribution-reporting-eligible', tp_count, 0)) AS attribution_reporting_eligible,
    MAX(IF(feature = 'attribution-reporting-register-source', tp_count, 0)) AS attribution_reporting_register_source,
    MAX(IF(feature = 'navigator.credentials.get', tp_count, 0)) AS navigator_credentials_get,
    MAX(IF(feature = 'IdentityProvider.getUserInfo', tp_count, 0)) AS IdentityProvider_getUserInfo,
    MAX(IF(feature = 'IdentityProvider.close', tp_count, 0)) AS IdentityProvider_close,
    MAX(IF(feature = 'navigator.login.setStatus', tp_count, 0)) AS navigator_login_setStatus,
    MAX(IF(feature = 'fencedFrameJs', tp_count, 0)) AS fencedFrameJs,
    MAX(IF(feature = 'FencedFrameConfig.setSharedStorageContext', tp_count, 0)) AS FencedFrameConfig_setSharedStorageContext,
    MAX(IF(feature = 'window.fence.getNestedConfigs', tp_count, 0)) AS window_fence_getNestedConfigs,
    MAX(IF(feature = 'window.fence.reportEvent', tp_count, 0)) AS window_fence_reportEvent,
    MAX(IF(feature = 'window.fence.setReportEventDataForAutomaticBeacons', tp_count, 0)) AS window_fence_setReportEventDataForAutomaticBeacons,
    MAX(IF(feature = 'fenced-frame', tp_count, 0)) AS fenced_frame,
    MAX(IF(feature = 'document.interestCohort', tp_count, 0)) AS document_interestCohort,
    MAX(IF(feature = 'privateAggregation.contributeToHistogram', tp_count, 0)) AS privateAggregation_contributeToHistogram,
    MAX(IF(feature = 'privateAggregation.contributeToHistogramOnEvent', tp_count, 0)) AS privateAggregation_contributeToHistogramOnEvent,
    MAX(IF(feature = 'privateAggregation.enableDebugMode', tp_count, 0)) AS privateAggregation_enableDebugMode,
    MAX(IF(feature = 'document.hasPrivateToken', tp_count, 0)) AS document_hasPrivateToken,
    MAX(IF(feature = 'document.hasRedemptionRecord', tp_count, 0)) AS document_hasRedemptionRecord,
    MAX(IF(feature = 'sec-private-state-token', tp_count, 0)) AS sec_private_state_token,
    MAX(IF(feature = 'sec-redemption-record', tp_count, 0)) AS sec_redemption_record,
    MAX(IF(feature = 'joinAdInterestGroup', tp_count, 0)) AS joinAdInterestGroup,
    MAX(IF(feature = 'leaveAdInterestGroup', tp_count, 0)) AS leaveAdInterestGroup,
    MAX(IF(feature = 'updateAdInterestGroups', tp_count, 0)) AS updateAdInterestGroups,
    MAX(IF(feature = 'clearOriginJoinedAdInterestGroups', tp_count, 0)) AS clearOriginJoinedAdInterestGroups,
    MAX(IF(feature = 'runAdAuction', tp_count, 0)) AS runAdAuction,
    MAX(IF(feature = 'generateBid', tp_count, 0)) AS generateBid,
    MAX(IF(feature = 'scoreAd', tp_count, 0)) AS scoreAd,
    MAX(IF(feature = 'reportWin', tp_count, 0)) AS reportWin,
    MAX(IF(feature = 'reportResult', tp_count, 0)) AS reportResult,
    MAX(IF(feature = 'window.sharedStorage.append', tp_count, 0)) AS window_sharedStorage_append,
    MAX(IF(feature = 'window.sharedStorage.clear', tp_count, 0)) AS window_sharedStorage_clear,
    MAX(IF(feature = 'window.sharedStorage.delete', tp_count, 0)) AS window_sharedStorage_delete,
    MAX(IF(feature = 'window.sharedStorage.set', tp_count, 0)) AS window_sharedStorage_set,
    MAX(IF(feature = 'window.sharedStorage.run', tp_count, 0)) AS window_sharedStorage_run,
    MAX(IF(feature = 'window.sharedStorage.selectURL', tp_count, 0)) AS window_sharedStorage_selectURL,
    MAX(IF(feature = 'window.sharedStorage.worklet.addModule', tp_count, 0)) AS window_sharedStorage_worklet_addModule,
    MAX(IF(feature = 'document.hasStorageAccess', tp_count, 0)) AS document_hasStorageAccess,
    MAX(IF(feature = 'document.hasUnpartitionedCookieAccess', tp_count, 0)) AS document_hasUnpartitionedCookieAccess,
    MAX(IF(feature = 'document.requestStorageAccess', tp_count, 0)) AS document_requestStorageAccess,
    MAX(IF(feature = 'document.requestStorageAccessFor', tp_count, 0)) AS document_requestStorageAccessFor,
    MAX(IF(feature = 'document.browsingTopics-false', tp_count, 0)) AS document_browsingTopics_false,
    MAX(IF(feature = 'document.browsingTopics-true', tp_count, 0)) AS document_browsingTopics_true,
    MAX(IF(feature = 'sec-browsing-topics-false', tp_count, 0)) AS sec_browsing_topics_false,
    MAX(IF(feature = 'sec-browsing-topics-true', tp_count, 0)) AS sec_browsing_topics_true,
    MAX(IF(feature = 'navigator.userAgentData.getHighEntropyValues', tp_count, 0)) AS navigator_userAgentData_getHighEntropyValues,
    MAX(IF(feature = 'Sec-CH-UA', tp_count, 0)) AS Sec_CH_UA,
    MAX(IF(feature = 'Sec-CH-UA-Arch', tp_count, 0)) AS Sec_CH_UA_Arch,
    MAX(IF(feature = 'Sec-CH-UA-Bitness', tp_count, 0)) AS Sec_CH_UA_Bitness,
    MAX(IF(feature = 'Sec-CH-UA-Full-Version', tp_count, 0)) AS Sec_CH_UA_Full_Version,
    MAX(IF(feature = 'Sec-CH-UA-Full-Version-List', tp_count, 0)) AS Sec_CH_UA_Full_Version_List,
    MAX(IF(feature = 'Sec-CH-UA-Mobile', tp_count, 0)) AS Sec_CH_UA_Mobile,
    MAX(IF(feature = 'Sec-CH-UA-Model', tp_count, 0)) AS Sec_CH_UA_Model,
    MAX(IF(feature = 'Sec-CH-UA-Platform', tp_count, 0)) AS Sec_CH_UA_Platform,
    MAX(IF(feature = 'Sec-CH-UA-Platform-Version', tp_count, 0)) AS Sec_CH_UA_Platform_Version,
    MAX(IF(feature = 'Sec-CH-UA-WoW64', tp_count, 0)) AS Sec_CH_UA_WoW64
  FROM distinct_features
  GROUP BY publisher
)

SELECT *
FROM pivoted_data
ORDER BY publisher
LIMIT 10000;
