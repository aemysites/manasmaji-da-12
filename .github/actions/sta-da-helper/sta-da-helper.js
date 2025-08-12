/*
 * Copyright 2025 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

import core from '@actions/core';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

// Adobe IMS token endpoint for OAuth 2.0 authorization access token exchange
const IMS_TOKEN_ENDPOINT = 'https://ims-na1.adobelogin.com/ims/token/v3';

/**
 * Get the org and site from the target URL.
 * @param {string} target - The target URL.
 * @returns {Object} - The org and site.
 * @throws {Error} - If the URL is invalid.
 */
function getOrgAndSiteFromTargetUrl(target) {
  try {
    const url = new URL(target);
    const pathSegments = url.pathname.split('/').filter((segment) => segment.length > 0);

    // last two segments are the org and site
    if (pathSegments.length >= 2) {
      const site = pathSegments[pathSegments.length - 1];
      const org = pathSegments[pathSegments.length - 2];
      return { org, site };
    } else {
      throw new Error('Target url does not contain enough path segments to determine org and site');
    }
  } catch (error) {
    throw new Error(`Error parsing target URL: ${error.message}. Target url: ${target}`);
  }
}

/**
 * Exchange Adobe IMS credentials for an access token using OAuth 2.0 authorization code flow
 * @param {string} clientId - Adobe IMS client ID from the service account
 * @param {string} clientSecret - Adobe IMS client secret from the service account
 * @param {string} serviceToken - Adobe IMS authorization code (obtained from service account)
 * @returns {Promise<string>} Access token for DA Admin API authentication
 */
export async function getAccessToken(clientId, clientSecret, serviceToken) {
  core.info('Exchanging IMS credentials for access token...');
  
  // Log parameter validation (without exposing sensitive values)
  core.info(`🔑 Using client_id: ${clientId.substring(0, 8)}... (length: ${clientId.length})`);
  core.info(`🔑 Using client_secret: ****** (length: ${clientSecret.length})`);
  core.info(`🔑 Using service_token: ${serviceToken.substring(0, 8)}... (length: ${serviceToken.length})`);

  // Prepare form-encoded data (matching the working curl request)
  const formParams = new URLSearchParams();
  formParams.append('grant_type', 'authorization_code');
  formParams.append('client_id', clientId);
  formParams.append('client_secret', clientSecret);
  formParams.append('code', serviceToken);

  core.info(`🌐 Making request to: ${IMS_TOKEN_ENDPOINT}`);
  core.info(`📝 Request body: grant_type=authorization_code&client_id=${clientId.substring(0, 8)}...&client_secret=******&code=${serviceToken.substring(0, 8)}...`);

  const response = await fetch(IMS_TOKEN_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: formParams.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    core.error(`❌ IMS token exchange failed ${response.status}: ${errorText}`);
    
    // Parse error response for better debugging
    try {
      const errorJson = JSON.parse(errorText);
      if (errorJson.error === 'invalid_client') {
        core.error('💡 Troubleshooting: The error "invalid_client" usually means:');
        core.error('   1. DA_CLIENT_ID is incorrect or not found');
        core.error('   2. DA_CLIENT_SECRET is incorrect or not found');
        core.error('   3. The client credentials are for a different environment');
        core.error('   4. The credentials have extra whitespace or encoding issues');
      } else if (errorJson.error === 'invalid_grant') {
        core.error('💡 Troubleshooting: The error "invalid_grant" usually means:');
        core.error('   1. DA_SERVICE_TOKEN (authorization code) is expired or invalid');
        core.error('   2. The service token has already been used');
        core.error('   3. The service token is for a different client');
      }
    } catch (parseError) {
      // Error text is not JSON, continue with original error
      core.error('💡 Raw error response (not JSON format)');
    }
    
    throw new Error(`Failed to exchange IMS credentials: ${response.status} ${errorText}`);
  }

  const tokenData = await response.json();

  if (!tokenData.access_token) {
    throw new Error('No access token received from IMS');
  }

  core.info('✅ Successfully obtained access token from IMS');
  return tokenData.access_token;
}

/**
 * Upload the content to DA.
 * @param {string} contentPath - The path to the content folder.
 * @param {string} target - The target URL (DA URL).
 * @param {string} token - The token to use to upload to DA.
 * @param {boolean} skipAssets - Whether to skip assets.
 * @returns {Promise<string[]>} - Returns the list of files that were uploaded.
 * @throws {Error} - If the upload fails.
 */
async function uploadToDa(contentPath, target, token, skipAssets) {
  const { org, site } = getOrgAndSiteFromTargetUrl(target);

  return new Promise((resolve, reject) => {
    const args = [
      '@adobe/aem-import-helper',
      'da',
      'upload',
      '--org', org,
      '--site', site,
      '--da-folder', `${contentPath}/da`,
      '--asset-list', `${contentPath}/asset-list.json`,
      '--token', token,
    ];

    if (skipAssets) {
      args.push('--skip-assets');
    }

    core.info('Running command:');
    const argsWithoutToken = args.filter((arg) => arg !== token);
    core.info(`${JSON.stringify(argsWithoutToken, null, 2)}`);

    const child = spawn('npx', args, {
      stdio: ['inherit', 'inherit', 'pipe'], // Pipe stderr to capture errors
      shell: true, // Required for `npx` to work correctly in some environments
    });

    let errorOutput = '';
    child.stderr.on('data', (data) => {
      core.info(data.toString());
      errorOutput = data.toString(); // Only save the last line (real error)
    });

    child.on('exit', (code) => {
      if (code === 0) {
        // now that our upload was complete, collect all files
        // recursively from the ${contentPath}/da
        const entries = fs.readdirSync(path.join(contentPath, 'da'), {
          recursive: true,
          withFileTypes: true,
        });

        const paths = entries
          .filter((entry) => entry.isFile())
          .map((entry) => {
            const fullPath = path.join(entry.parentPath, entry.name);
            return `/${fullPath.replace(/^.*?da\//, '')}`;
          });
        resolve(paths);
      } else {
        reject(new Error(`sta-da-helper failed. Error: ${errorOutput}`));
      }
    });
  });
}

/**
 * Validate that the zip content contains what we expect, it should have a folder called da,
 * and a file called asset-list.json.
 * @param {string} contentPath - The path to the zip content.
 * @returns {void} - Throws an error if the content is missing.
 */
function checkForRequiredContent(contentPath) {
  const daFolder = path.join(contentPath, 'da');
  const assetListFile = path.join(contentPath, 'asset-list.json');

  if (!fs.existsSync(daFolder)) {
    throw new Error('DA folder not found');
  }

  if (!fs.existsSync(assetListFile)) {
    throw new Error('asset-list.json file not found');
  }
}

/**
 * Performs DA preview or publish operation using the DA Admin API
 * @param {string[]} pages - Array of page paths to preview/publish
 * @param {string} operation - Either 'preview' or 'previewAndPublish'
 * @param {string} context - AEMY context containing project info
 * @param {string} token - DA access token
 */
async function doDAPreviewPublish(pages, operation, context, token) {
  const { project } = JSON.parse(context);
  const { owner, repo, branch = 'main' } = project;

  if (!owner || !repo) {
    throw new Error('Invalid context format: missing owner or repo.');
  }

  const report = {
    successes: 0,
    failures: 0,
    failureList: {
      preview: [],
      publish: [],
    },
  };

  // For previewAndPublish, we do both operations
  const operations = operation === 'previewAndPublish' ? ['preview', 'live'] : ['preview'];
  
  for (const op of operations) {
    const baseUrl = `https://admin.hlx.page/${op}/${owner}/${repo}/${branch}`;
    
    for (const page of pages) {
      // Remove leading slash and ensure proper path format  
      const cleanPath = page.startsWith('/') ? page.substring(1) : page;
      const url = `${baseUrl}/${cleanPath}`;
      
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: '{}',
        });

        if (response.ok) {
          const operationName = op === 'live' ? 'publish' : op;
          core.info(`✓ ${operationName} success: ${page}`);
          report.successes += 1;
        } else {
          const errorText = await response.text();
          const operationName = op === 'live' ? 'publish' : op;
          core.info(`.${operationName} operation failed on ${page}: ${response.status} : ${response.statusText} : ${errorText}`);
          
          if (response.status === 401) {
            core.warning(`❌ Operation failed: The token is invalid.`);
          } else {
            core.warning(`❌ Operation failed on ${page}: ${errorText}`);
          }
          
          report.failures += 1;
          // Store failures under the user-facing name (publish instead of live)
          const failureKey = op === 'live' ? 'publish' : op;
          report.failureList[failureKey].push(page);
        }
      } catch (error) {
        const operationName = op === 'live' ? 'publish' : op;
        core.warning(`❌ ${operationName} failed for ${page}: ${error.message}`);
        report.failures += 1;
        const failureKey = op === 'live' ? 'publish' : op;
        report.failureList[failureKey].push(page);
      }
    }
  }

  core.setOutput('successes', report.successes);
  core.setOutput('failures', report.failures);

  if (report.failures > 0) {
    core.warning(`❌ The pages that failed are: ${JSON.stringify(report.failureList, undefined, 2)}`);
    const totalExpected = operations.length * pages.length;
    core.setOutput('error_message', `❌ Error: Failed to ${operation} ${report.failures} of ${totalExpected} operations.`);
  }
}

/**
* Main function for the GitHub Action.
*
* Depending on the provided operation, different outputs are set:
* All operations can set the error_message output.
*
* |---------------------------------------------------------------------|
* | operation          | output                                         |
* |---------------------------------------------------------------------|
* | upload             | paths - the list of files that were uploaded   |
* |---------------------------------------------------------------------|
* | preview            | successes - number of successful operations    |
* |                    | failures - number of failures                  |
* |---------------------------------------------------------------------|
* | previewAndPublish  | successes - number of successful operations    |
* |                    | failures - number of failures                  |
* |---------------------------------------------------------------------|
* |  *                 | error_message - string describing the error    |
* |---------------------------------------------------------------------|
*
*/
export async function run() {
  const operation = core.getInput('operation');

  if (operation === 'upload') {
    // the target to upload to
    const target = core.getInput('target');

    // this is the folder that contains the extracted zip content
    const contentPath = core.getInput('content_path');

    // aem-import-helper can skip assets if needed
    const skipAssets = core.getInput('skip_assets') || false;

    // DA IMS credentials for token exchange
    const clientId = process.env.DA_CLIENT_ID;
    const clientSecret = process.env.DA_CLIENT_SECRET;
    const serviceToken = process.env.DA_SERVICE_TOKEN;

    try {
      // Validate required IMS credentials
      if (!clientId || !clientSecret || !serviceToken) {
        throw new Error('Missing required DA credentials: DA_CLIENT_ID, DA_CLIENT_SECRET, and DA_SERVICE_TOKEN must be set');
      }

      // Log credential validation (without exposing sensitive values)
      core.info(`✅ DA_CLIENT_ID present: ${clientId ? 'yes' : 'no'} (length: ${clientId?.length || 0})`);
      core.info(`✅ DA_CLIENT_SECRET present: ${clientSecret ? 'yes' : 'no'} (length: ${clientSecret?.length || 0})`);
      core.info(`✅ DA_SERVICE_TOKEN present: ${serviceToken ? 'yes' : 'no'} (length: ${serviceToken?.length || 0})`);
      
      // Trim whitespace from credentials (common issue)
      const trimmedClientId = clientId.trim();
      const trimmedClientSecret = clientSecret.trim();
      const trimmedServiceToken = serviceToken.trim();
      
      if (trimmedClientId !== clientId) core.info('⚠️ Trimmed whitespace from DA_CLIENT_ID');
      if (trimmedClientSecret !== clientSecret) core.info('⚠️ Trimmed whitespace from DA_CLIENT_SECRET');
      if (trimmedServiceToken !== serviceToken) core.info('⚠️ Trimmed whitespace from DA_SERVICE_TOKEN');

      // Exchange IMS credentials for access token
      const accessToken = await getAccessToken(trimmedClientId, trimmedClientSecret, trimmedServiceToken);

      checkForRequiredContent(contentPath);
      const files = await uploadToDa(contentPath, target, accessToken, skipAssets);
      core.setOutput('paths', files);
    } catch (error) {
      core.error(`DA Error: ${error.message}`);
      core.setOutput('error_message', `❌ Error during DA upload: ${error.message}`);
    }
  } else if (operation === 'preview' || operation === 'previewAndPublish') {
    // DA preview/publish operations
    const pagesInput = core.getInput('pages');
    const context = core.getInput('context');
    
    try {
      const pages = JSON.parse(pagesInput);
      
      // Get DA credentials for token exchange
      const clientId = process.env.DA_CLIENT_ID;
      const clientSecret = process.env.DA_CLIENT_SECRET;
      const serviceToken = process.env.DA_SERVICE_TOKEN;

      // Validate required IMS credentials
      if (!clientId || !clientSecret || !serviceToken) {
        throw new Error('Missing required DA credentials: DA_CLIENT_ID, DA_CLIENT_SECRET, and DA_SERVICE_TOKEN must be set');
      }

      // Log credential validation (without exposing sensitive values)
      core.info(`✅ DA_CLIENT_ID present: ${clientId ? 'yes' : 'no'} (length: ${clientId?.length || 0})`);
      core.info(`✅ DA_CLIENT_SECRET present: ${clientSecret ? 'yes' : 'no'} (length: ${clientSecret?.length || 0})`);
      core.info(`✅ DA_SERVICE_TOKEN present: ${serviceToken ? 'yes' : 'no'} (length: ${serviceToken?.length || 0})`);
      
      // Trim whitespace from credentials (common issue)
      const trimmedClientId = clientId.trim();
      const trimmedClientSecret = clientSecret.trim();
      const trimmedServiceToken = serviceToken.trim();
      
      if (trimmedClientId !== clientId) core.info('⚠️ Trimmed whitespace from DA_CLIENT_ID');
      if (trimmedClientSecret !== clientSecret) core.info('⚠️ Trimmed whitespace from DA_CLIENT_SECRET');
      if (trimmedServiceToken !== serviceToken) core.info('⚠️ Trimmed whitespace from DA_SERVICE_TOKEN');

      // Exchange IMS credentials for access token
      const accessToken = await getAccessToken(trimmedClientId, trimmedClientSecret, trimmedServiceToken);
      
      // Perform DA preview/publish operations
      await doDAPreviewPublish(pages, operation, context, accessToken);
    } catch (error) {
      core.error(`DA Preview/Publish Error: ${error.message}`);
      core.setOutput('error_message', `❌ Error during DA ${operation}: ${error.message}`);
    }
  } else {
    core.error(`Invalid operation: ${operation}. Supported operations are 'upload', 'preview', 'previewAndPublish'.`);
  }
}

await run();
