/**
 *
 * Copyright 2021 Alexandru Bagu <alexandru.bagu@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "pf_log.h"
#include "modules_api.h"
#include "pf_config.h"

#define TAG MODULE_TAG("external-target-resolve")

#define PLUGIN_NAME "external-target-resolve"
#define PLUGIN_DESC "plugin to resolve target based on connection parameters"
#define EXTERNAL_SCRIPT "./freerdp-external-target-resolve"

static proxyPluginsManager* g_plugins_manager = NULL;
static char external_script_fullpath [PATH_MAX+1];

static char* dup_if_not_empty(char* ptr) {
  if(ptr && strlen(ptr)) {
    return _strdup(ptr);
  }
  return NULL;
}

static void free_if_not_null(char* ptr) {
  if(ptr) {
    free(ptr);
  }
}

static char* ifnull(char* arg1, char* arg2) {
  if(arg1) return arg1;
  return arg2;
}

static BOOL server_fetch_target_addr(proxyData* pdata, void* param)
{
  pClientContext* pc = pdata->pc;
  pServerContext* ps = pdata->ps;
  rdpContext* context = &pc->context;
  rdpSettings* settings = context->settings;
  proxyFetchTargetEventInfo* result = (proxyFetchTargetEventInfo*)param;

  char* username = NULL, *proxyUsername = NULL, *gatewayUsername = NULL;
  char* domain = NULL, *gatewayDomain = NULL;
  char* password = NULL, *proxyPassword = NULL, *gatewayPassword = NULL;
  char* clientHostname = NULL, *proxyHostname = NULL, *gatewayHostname = NULL;
  char* routingToken = NULL;
  FILE *fp;
  char empty_str[2] = "";
  
  if (settings) {
      username = dup_if_not_empty(settings->Username);
      proxyUsername = dup_if_not_empty(settings->ProxyUsername);
      gatewayUsername = dup_if_not_empty(settings->GatewayUsername);

      domain = dup_if_not_empty(settings->Domain);
      gatewayDomain = dup_if_not_empty(settings->GatewayDomain);

      password = dup_if_not_empty(settings->Password);
      proxyPassword = dup_if_not_empty(settings->ProxyPassword);
      gatewayPassword = dup_if_not_empty(settings->GatewayPassword);
      
      clientHostname = dup_if_not_empty(settings->ClientHostname);
      proxyHostname = dup_if_not_empty(settings->ProxyHostname);
      gatewayHostname = dup_if_not_empty(settings->GatewayHostname);
  }

	DWORD routing_token_length;
	const char* routing_token = freerdp_nego_get_routing_token((rdpContext*)ps, &routing_token_length);
  routingToken = dup_if_not_empty((char*)routing_token);

  int fd[2];
  if (pipe(fd) >= 0) {
    pid_t child_pid = fork();
    if(child_pid >= 0) {
      if(child_pid) {
        // parent process
        
        // wait for child to exit
        int returnStatus;    
        waitpid(child_pid, &returnStatus, 0);

        // read result
        char externalResult[8192];
        read(fd[0], externalResult, sizeof(externalResult));

        proxyConfig* cfg = pf_server_config_load_buffer(externalResult);
        if (cfg) {
          pdata->config = cfg;
          result->fetch_method = PROXY_FETCH_TARGET_USE_CUSTOM_ADDR;
          result->target_address = _strdup(pdata->config->TargetHost);
          result->target_port = pdata->config->TargetPort;
          WLog_INFO(TAG, "Routing for [%s]\\[%s]: [%s]:[%d]", domain, username, result->target_address, result->target_port);
        }
      } else { 
        // child process
        
        // set environment variables
        setenv("FreeRDP_Username", ifnull(username, empty_str), TRUE);
        setenv("FreeRDP_ProxyUsername", ifnull(proxyUsername, empty_str), TRUE);
        setenv("FreeRDP_GatewayUsername", ifnull(gatewayUsername, empty_str), TRUE);
        setenv("FreeRDP_Domain", ifnull(domain, empty_str), TRUE);
        setenv("FreeRDP_GatewayDomain", ifnull(gatewayDomain, empty_str), TRUE);
        setenv("FreeRDP_Password", ifnull(password, empty_str), TRUE);
        setenv("FreeRDP_ProxyPassword", ifnull(proxyPassword, empty_str), TRUE);
        setenv("FreeRDP_GatewayPassword", ifnull(gatewayPassword, empty_str), TRUE);
        setenv("FreeRDP_ClientHostname", ifnull(clientHostname, empty_str), TRUE);
        setenv("FreeRDP_ProxyHostname", ifnull(proxyHostname, empty_str), TRUE);
        setenv("FreeRDP_GatewayHostname", ifnull(gatewayHostname, empty_str), TRUE);
        setenv("FreeRDP_RoutingToken", ifnull(routingToken, empty_str), TRUE);

        // start excternal script
        fp = popen(external_script_fullpath, "r");
        if (fp != NULL) {
          char externalResult[16384];
          int pos = 0, max = sizeof(externalResult) - 1;
          while(pos <= max && fgets(externalResult + pos, max - pos, fp)) {
            pos += strlen(externalResult + pos);
          }

          write(fd[1], externalResult, strlen(externalResult) + 1);
          pclose(fp);
        }
        exit(0);
      }
    }
  }

  free_if_not_null(username);
  free_if_not_null(proxyUsername);
  free_if_not_null(gatewayUsername);
  free_if_not_null(domain);
  free_if_not_null(gatewayDomain);
  free_if_not_null(password);
  free_if_not_null(proxyPassword);
  free_if_not_null(gatewayPassword);
  free_if_not_null(clientHostname);
  free_if_not_null(proxyHostname);
  free_if_not_null(gatewayHostname);
  free_if_not_null(routingToken);
	return TRUE;
}

static BOOL stub_proxy_hook(proxyData* pdata, void* param) { return TRUE; }

static proxyPlugin external_target_resolve_plugin = {
	PLUGIN_NAME,                /* name */
	PLUGIN_DESC,                /* description */
	NULL,                       /* PluginUnload */
	stub_proxy_hook,            /* ClientPreConnect */
	stub_proxy_hook,            /* ClientPostConnect */
	stub_proxy_hook,            /* ClientLoginFailure */
	stub_proxy_hook,            /* ClientEndPaint */
	stub_proxy_hook,            /* ServerPostConnect */
	stub_proxy_hook,            /* ServerChannelsInit */
	stub_proxy_hook,            /* ServerChannelsFree */
	stub_proxy_hook,            /* ServerSessionEnd */
	stub_proxy_hook,            /* KeyboardEvent */
	stub_proxy_hook,            /* MouseEvent */
	stub_proxy_hook,            /* ClientChannelData */
	stub_proxy_hook,            /* ServerChannelData */
	server_fetch_target_addr    /* ServerFetchTargetAddr */
};

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager)
{
	g_plugins_manager = plugins_manager;
  realpath(EXTERNAL_SCRIPT, external_script_fullpath);
  if( access( external_script_fullpath, F_OK ) == 0 ) {
    WLog_INFO(TAG, "Hello! We are going to use [%s] as external script.", external_script_fullpath);
	  return plugins_manager->RegisterPlugin(&external_target_resolve_plugin);
  } else {
    WLog_ERR(TAG, "Hello! External script [%s] does not exist.", external_script_fullpath);
    return FALSE;
  }
}

