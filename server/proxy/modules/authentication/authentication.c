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

#include <freerdp/freerdp.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <freerdp/server/proxy/proxy_log.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <winpr/cmdline.h>

#define TAG MODULE_TAG("authentication")

#define PLUGIN_NAME "authentication"
#define PLUGIN_DESC "plugin to authentication target based on connection parameters"
#define AUTHENTICATION_SCRIPT "./freerdp-proxy-authentication"
#define AUTHENTICATION_SCRIPT_ENV "AUTHENTICATION_SCRIPT"

static char authentication_script_fullpath [PATH_MAX+1];

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

static BOOL copy_string_list(char*** dst, size_t* size, char** src, size_t srcSize)
{
	WINPR_ASSERT(dst);
	WINPR_ASSERT(size);
	WINPR_ASSERT(src || (srcSize == 0));

	*dst = NULL;
	*size = 0;
	if (srcSize == 0)
		return TRUE;
	{
		char* csv = CommandLineToCommaSeparatedValues(srcSize, src);
		*dst = CommandLineParseCommaSeparatedValues(csv, size);
		free(csv);
	}

	return TRUE;
}

void copy_authentication_data(proxyConfig* config, const proxyConfig* auth_config) {
  config->FixedTarget = auth_config->FixedTarget;
  free(config->TargetHost);
  config->TargetHost = dup_if_not_empty(auth_config->TargetHost);
  config->TargetPort = auth_config->TargetPort;

  config->Keyboard = auth_config->Keyboard;
  config->Mouse = auth_config->Mouse;
  config->Multitouch = auth_config->Multitouch;

  config->ServerTlsSecurity = auth_config->ServerTlsSecurity;
  config->ServerRdpSecurity = auth_config->ServerRdpSecurity;
  config->ServerNlaSecurity = auth_config->ServerNlaSecurity;

  config->ClientNlaSecurity = auth_config->ClientNlaSecurity;
  config->ClientTlsSecurity = auth_config->ClientTlsSecurity;
  config->ClientRdpSecurity = auth_config->ClientRdpSecurity;
  config->ClientAllowFallbackToTls = auth_config->ClientAllowFallbackToTls;

  config->GFX = auth_config->GFX;
  config->DisplayControl = auth_config->DisplayControl;
  config->Clipboard = auth_config->Clipboard;
  config->AudioOutput = auth_config->AudioOutput;
  config->AudioInput = auth_config->AudioInput;
  config->RemoteApp = auth_config->RemoteApp;
  config->DeviceRedirection = auth_config->DeviceRedirection;
  config->VideoRedirection = auth_config->VideoRedirection;
  config->CameraRedirection = auth_config->CameraRedirection;
  
  free(config->Passthrough);
  if (!copy_string_list(&config->Passthrough, &config->PassthroughCount, auth_config->Passthrough, auth_config->PassthroughCount))
  config->PassthroughIsBlacklist = auth_config->PassthroughIsBlacklist;

  config->TextOnly = auth_config->TextOnly;
  config->MaxTextLength = auth_config->MaxTextLength;

  config->DecodeGFX = auth_config->DecodeGFX;
}

static BOOL server_fetch_target_addr(proxyPlugin* plugin, proxyData* pdata, void* param)
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
        char cfgbuf[65536];
        read(fd[0], cfgbuf, sizeof(cfgbuf));

        const proxyConfig* cfg = pf_server_config_load_buffer(cfgbuf);
        if (cfg) {
          copy_authentication_data((proxyConfig*)pdata->config, cfg);
          free((proxyConfig*)cfg);

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
        fp = popen(authentication_script_fullpath, "r");
        if (fp != NULL) {
          char buf[128];
          int pos;
          while((pos = fread(buf, 1, sizeof(buf), fp))) {
            write(fd[1], buf, pos);
          }
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

#ifdef __cplusplus
extern "C"
{
#endif
	FREERDP_API BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata);
#ifdef __cplusplus
}
#endif

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata)
{
	proxyPlugin plugin = {};

	plugin.name = PLUGIN_NAME;
	plugin.description = PLUGIN_DESC;
	plugin.ServerFetchTargetAddr = server_fetch_target_addr;
	plugin.userdata = userdata;

  char* auth_script = getenv(AUTHENTICATION_SCRIPT_ENV);
  if(auth_script) {
    realpath(auth_script, authentication_script_fullpath);
  } else {
    realpath(AUTHENTICATION_SCRIPT, authentication_script_fullpath);
  }
  if( access( authentication_script_fullpath, F_OK ) == 0 ) {
    WLog_INFO(TAG, "[Authentication] Using [%s]", authentication_script_fullpath);
	  return plugins_manager->RegisterPlugin(plugins_manager, &plugin);
  } else {
    WLog_ERR(TAG, "[Authentication] Script [%s] does not exist. To override it use ENV [%s]", authentication_script_fullpath, AUTHENTICATION_SCRIPT_ENV);
    return FALSE;
  }
}