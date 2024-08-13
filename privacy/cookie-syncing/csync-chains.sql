-- Captures cookie-syncing inclusion chains to measure prevalence of cookie syncing under the purview of privacy
-- Approach is followed from https://umariqbal.com/papers/khaleesi-usenix2022.pdf
-- Chains are identified based on the following details:
-- 1. Query parameters
-- 2. Cookie-related headers (Cookie and Set-Cookie headers)
-- 3. Non-standard headers
-- Only TokenizedRequests has been tested

-- Function to obtain the identifier tokens
CREATE TEMP FUNCTION ExtractTokens(input STRING, type STRING) AS (
  ARRAY(
    SELECT AS STRUCT 
      type AS token_type,
      key_value[OFFSET(0)] AS token_name,
      key_value[SAFE_OFFSET(1)] AS token_value
    FROM UNNEST(SPLIT(input, '; ')) AS pair
    CROSS JOIN UNNEST([STRUCT(SPLIT(pair, '=') AS key_value)])
    WHERE LENGTH(key_value[SAFE_OFFSET(1)]) >= 8
      AND LOWER(key_value[OFFSET(0)]) NOT IN ('expires', 'max-age', 'domain')
  )
);

-- Function to obtain the BASE64 version of an identifier token
CREATE TEMP FUNCTION HashToken(token STRING) AS (
  TO_BASE64(SAFE_CAST(token AS BYTES))
);

-- Function to obtain the MD5-hash version of an identifier token
CREATE TEMP FUNCTION MD5Hash(token STRING) AS (
  LOWER(TO_HEX(MD5(SAFE_CAST(token AS BYTES))))
);

-- Function to obtain the SHA1-hash version of an identifier token
CREATE TEMP FUNCTION SHA1Hash(token STRING) AS (
  LOWER(TO_HEX(SHA1(SAFE_CAST(token AS BYTES))))
);

WITH TokenizedRequests AS (
  SELECT
    pages.rank,
    NET.REG_DOMAIN(requests.page) AS publisher,
    requests.url,
    -- Extract third-party domains from requests
    REGEXP_EXTRACT(requests.url, r'https?://([^/]+)') AS third_party_domain,
    ARRAY_CONCAT(
      -- Tokens from 'Cookie' headers
      ARRAY(
        SELECT AS STRUCT token_type, token_name, token_value, 
                        HashToken(token_value) AS base64_token,
                        MD5Hash(token_value) AS md5_token,
                        SHA1Hash(token_value) AS sha1_token
        FROM UNNEST(requests.request_headers) AS COOKIE,
             UNNEST(ExtractTokens(COOKIE.value, 'cookie')) AS token_struct
        WHERE LOWER(COOKIE.name) = 'cookie'
      ),
      -- Tokens from 'Set-Cookie' headers
      ARRAY(
        SELECT AS STRUCT token_type, token_name, token_value,
                        HashToken(token_value) AS base64_token,
                        MD5Hash(token_value) AS md5_token,
                        SHA1Hash(token_value) AS sha1_token
        FROM UNNEST(requests.response_headers) AS COOKIE,
             UNNEST(ExtractTokens(COOKIE.value, 'set-cookie')) AS token_struct
        WHERE LOWER(COOKIE.name) = 'set-cookie'
      ),
      -- Tokens from query parameters in the URL
      ARRAY(
        SELECT AS STRUCT 'query-parameter' AS token_type, 
                        REGEXP_REPLACE(key_value[OFFSET(0)], r'^\?', '') AS token_name, 
                        key_value[SAFE_OFFSET(1)] AS token_value,
                        HashToken(key_value[SAFE_OFFSET(1)]) AS base64_token,
                        MD5Hash(key_value[SAFE_OFFSET(1)]) AS md5_token,
                        SHA1Hash(key_value[SAFE_OFFSET(1)]) AS sha1_token
        FROM UNNEST(SPLIT(REGEXP_EXTRACT(requests.url, r'\?.*$'), '&')) AS param
        CROSS JOIN UNNEST([STRUCT(SPLIT(param, '=') AS key_value)])
        WHERE LENGTH(key_value[SAFE_OFFSET(1)]) >= 8
      ),
      -- Tokens from non-standard request headers
      ARRAY(
        SELECT AS STRUCT token_type, token_name, token_value,
                        HashToken(token_value) AS base64_token,
                        MD5Hash(token_value) AS md5_token,
                        SHA1Hash(token_value) AS sha1_token
        FROM UNNEST(requests.request_headers) AS header,
             UNNEST(ExtractTokens(header.value, 'header')) AS token_struct
        WHERE LOWER(header.name) NOT IN (
          'cookie', 'set-cookie', 'host', 'user-agent', 'accept', 'accept-language', 'accept-encoding', 'referer', 'sec-ch-ua', 'sec-fetch-site', 'content-type', 'connection'
        )
      )
    ) AS tokens
  FROM `httparchive.all.requests` AS requests
  JOIN `httparchive.all.pages` AS pages
  ON NET.REG_DOMAIN(requests.page) = NET.REG_DOMAIN(pages.page)
  WHERE 
    requests.date = '2024-06-01' AND
    pages.date = '2024-06-01' AND
    requests.client = 'desktop' AND
    pages.client = 'desktop' AND
    requests.is_root_page = true AND
    pages.rank < 1000
),
TokenGroups AS (
  SELECT
    t1.publisher,
    t1.third_party_domain,
    token.token_value,
    token.token_type,
    token.token_name,
    token.base64_token,
    token.md5_token,
    token.sha1_token,
    matched_token.token_value AS matched_token_value,
    matched_token.token_type AS matched_token_type,
    matched_token.token_name AS matched_token_name,
    t2.third_party_domain AS matched_third_party_domain
  FROM TokenizedRequests t1
  CROSS JOIN UNNEST(t1.tokens) AS token
  LEFT JOIN TokenizedRequests t2
  ON t1.publisher = t2.publisher
  LEFT JOIN UNNEST(t2.tokens) AS matched_token
  ON (
    token.token_value = matched_token.token_value OR
    token.token_value = matched_token.base64_token OR
    token.token_value = matched_token.md5_token OR
    token.token_value = matched_token.sha1_token OR
    token.base64_token = matched_token.token_value OR
    token.md5_token = matched_token.token_value OR
    token.sha1_token = matched_token.token_value
  )
  WHERE token.token_value IS NOT NULL
)
SELECT
  publisher,
  token_value,
  STRING_AGG(DISTINCT matched_third_party_domain, ', ') AS third_party_domains,
  COUNT(DISTINCT matched_third_party_domain) AS distinct_third_party_domains,
  STRING_AGG(DISTINCT matched_token_type, ', ') AS token_exchange_methods,
  COUNT(DISTINCT matched_token_name) AS distinct_token_names
FROM TokenGroups
GROUP BY publisher, token_value;
