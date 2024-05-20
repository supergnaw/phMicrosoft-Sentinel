# File: mcirosoftsentinel_connector.py
#
# Licensed under the Apache License, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either expressed or implied. See the License for the specific language governing permissions
# and limitations under the License.

import json

# Phantom imports
import phantom.app as phantom
import phantom.rules as phanrules
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from requests import Response

from mcirosoftsentinel_consts import *

# Custom helper classes
from authentication_token import AuthenticationToken
from settings_parser import SettingsParser
import replus


def parse_exception_message(e: Exception) -> str:
    try:
        if 1 < len(e.args):
            return f"Exception [{e.args[0]}]: {e.args[1]}"
        return f"Exception: {e.args[0]}"
    except Exception:
        return "Failed to parse exception error message"


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SentinelConnector(BaseConnector):
    """
    Normalization Properties

    Phantom has a somewhat obtuse way of accessing app information such as versions, names, etc., through the use of API
    calls. Because of this, these properties are meant to provide a more direct way to access this data. These values
    are stored within the class and initialized as None until they are called. After the first use, the value is updated
    via an API call, which is then used for each successive usage, reducing internal API calls and releasing resources
    for other computational requirements.

    :property self.app_json:
    :property self.app_id:
    :property self.app_version:
    :property self.asset_name:
    :property self.label:
    :property self.tags:
    :property self.action_id:
    :property self.action_result:
    """

    @property
    def app_id(self) -> str:
        if not self._app_id:
            self._app_id = str(self.get_app_json().get("appid", 'unknown app id'))
        return self._app_id

    _app_id: str = None

    @property
    def app_version(self) -> str:
        if not self._app_version:
            self._app_version = str(self.get_app_json().get("app_version", '0.0.0'))
        return self._app_version

    _app_version: str = None

    @property
    def asset_id(self) -> str:
        if not self._asset_id:
            self._asset_id = str(self.get_asset_id())
        return self._asset_id

    _asset_id: str = None

    @property
    def asset_name(self) -> str:
        if not self._asset_name:
            self._asset_name = phantom.requests.get(
                phanrules.build_phantom_rest_url("asset", self.asset_id),
                verify=self.config.verify_server_cert
            ).json.get("name", 'unnamed_asset')
        return self._asset_name

    _asset_name: str = None

    @property
    def label(self) -> str:
        if not self._label:
            self._label = phantom.requests.get(
                phanrules.build_phantom_rest_url("asset", self.asset_id),
                verify=self.config.verify_server_cert
            ).json.get("configuration", {}).get("ingest", {}).get("container_label", 'events')
        return self._label

    _label: str = None

    @property
    def tags(self) -> list:
        if not self._tags:
            self._tags = phantom.requests.get(
                phanrules.build_phantom_rest_url("asset", self.asset_id),
                verify=self.config.verify_server_cert
            ).json.get("tags", [])
        return self._tags

    _tags: list = None

    @property
    def action_id(self) -> str:
        if not self._action_id:
            self._action_id = str(self.get_action_identifier())
        return self._action_id

    _action_id: str = None

    @property
    def config_defaults(self) -> dict:
        if not self._config_defaults:
            defaults = {}
            for default_name, meta_data in self.get_app_json().get("configuration", {}).items():
                if "ph" == meta_data["data_type"]:
                    continue

                if "numeric" == meta_data["data_type"]:
                    defaults[default_name] = int(meta_data.get("default", 0))
                elif "boolean" == meta_data["data_type"]:
                    defaults[default_name] = bool(meta_data.get("default", False))
                else:
                    defaults[default_name] = str(meta_data.get("default", "None"))
            self._config_defaults = defaults
        return self._config_defaults

    _config_defaults: dict = None

    @property
    def action_result(self) -> ActionResult:
        if not self._action_result:
            self._action_result = self.add_action_result(ActionResult({'action started': self.action_id}))
        return self._action_result

    _action_result: ActionResult = None

    def __init__(self):

        # Call the BaseConnectors init first
        super(SentinelConnector, self).__init__()

        # New version class variables
        self.state = None
        self.tokens: dict = {"sentinel": AuthenticationToken(token=""), "loganalytics": AuthenticationToken(token="")}
        self.config: SettingsParser = None

    # ========== #
    # REST CALLS #
    # ========== #

    # ------------------- #
    # Primary REST Caller #
    # ------------------- #

    def _make_rest_call(self, endpoint: str, method: str = "get", verify: bool = False, **kwargs) -> RetVal:
        # Make sure REST method exists in requests
        try:
            request_func = getattr(phantom.requests, method.lower())
        except AttributeError:
            message = f"Invalid requests method: {method}"
            self.error_print(message)
            return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

        # Default headers and add authorization token as necessary
        if "headers" not in kwargs:
            kwargs["headers"] = {"Content-Type": "application/json"}
        if self._requires_token(endpoint):
            kwargs["headers"]["Authorization"] = f"Bearer {self._get_token(endpoint)}"

        # Try the REST call and return the processed response or the exception error
        try:
            self.debug_print("Endpoint:", endpoint)
            self.debug_print("Headers:", kwargs.get("headers", None))
            self.debug_print("Query parameters:", kwargs.get("params", None))
            return self._process_response(request_func(endpoint, verify=verify, **kwargs))
        except Exception as e:
            message = f"REST call Exception: {parse_exception_message(e)}"
            self.error_print(message)
            self.action_result.set_status(phantom.APP_ERROR, message)
            return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message))

    # ------------------- #
    # Response Processors #
    # ------------------- #

    def _process_response(self, response: Response = None) -> RetVal:
        """
        Processes a requests response object according to the content type.

        :param response: requests response object
        :return: [status, JSON|message]
        """
        # store raw debug data, it will get dumped in the logs if the action fails
        if hasattr(self.action_result, 'add_debug_data'):
            self.action_result.add_debug_data({'r_status_code': response.status_code})
            self.action_result.add_debug_data({'r_text': response.text})
            self.action_result.add_debug_data({'r_headers': response.headers})

        if 200 > response.status_code > 399:
            return self._process_error_response(response)

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response)

        # Process an HTML response in case a proxy error is returned
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response)

        # everything else is actually an error at this point
        error_text = response.text.replace('{', '{{').replace('}', '}}')
        message = (f"Can't process response from server."
                   f"Status Code: {response.status_code} Data from server: {error_text}")
        self.error_print(message)
        return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

    def _process_error_response(self, response: Response = None) -> RetVal:
        message = response.text
        self.debug_print("error response:", message)
        self.error_print(message)
        return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

    def _process_json_response(self, response: Response = None) -> RetVal:
        """
        Attempts to parse a JSON content response.

        :param response: request response object
        :return: [status, JSON|message]
        """
        try:
            resp_json = response.json()
            if 200 <= response.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, resp_json)
        except Exception as e:
            message = f"Unable to parse JSON response. Error: {parse_exception_message(e)}"
            self.error_print(message)
            return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

        # Please specify the status codes here

        # You should process the error returned in the json
        error_text = response.text.replace(u'{', '{{').replace(u'}', '}}')
        message = f"Error from server. Status Code: {response.status_code} Data from server: {error_text}"
        self.error_print(message)

        return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

    def _process_html_response(self, response: Response = None) -> RetVal:
        """
        Treats an HTML response like an error.

        :param response: request response object
        :return: [status, message]
        """
        try:
            error_text = replus.sub(r"/\s+/m", " ", replus.sub(r"/<[^>]*>/", "", response.text))
        except:
            error_text = "Cannot parse error details"

        message = f"Status Code: {response.status_code}. Data from server:\n{error_text}\n"
        message = message.replace(u'{', '{{').replace(u'}', '}}')
        self.error_print(message)
        return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

    def _process_empty_response(self, response: Response = None) -> RetVal:
        """
        Verifies an empty response for when a 200 status code is returned but the response has no content.

        :param response: request response object
        :return: [status, None]
        """
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        message = "Empty response and no information in the header"
        self.error_print(message)
        return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), None)

    # ============== #
    # AUTHENTICATION #
    # ============== #

    # --------------------- #
    # Authentication Tokens #
    # --------------------- #

    def _authenticate(self, resource: str = "sentinel", force_refresh: bool = False) -> bool:
        """
        Checks for an authentication token for a given resource, and if none exist, generates a new one

        :param resource: the resource to authenticate with, 'sentinel' or 'loganalytics'
        :param force_refresh: force a refresh of the authentication tokens if saved in cache
        :return: bool
        """
        if not self.tokens.get(resource, False) or force_refresh:
            self.tokens[resource] = AuthenticationToken(token="")

        # AuthenticationToken allocated has not yet expired
        if self.tokens[resource].token:
            summary = self.tokens[resource].summary()
            message = f"Authentication for {resource} valid until {summary['expires_on']} ({summary['expires_in']})"
            self.save_progress(message)
            return self.action_result.set_status(phantom.APP_SUCCESS, message)

        endpoint = self._get_login_uri(resource)

        # Prepare to request a new token
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": self._get_scope(resource),
            "grant_type": "client_credentials"
        }

        self.debug_print("Authentication:", f"Attempting to authenticate to {endpoint}")
        self.debug_print("Requested scope:", self._get_scope(resource))

        status, resp_json = self._make_rest_call(endpoint=endpoint, headers=headers, data=data, verify=False)

        if phantom.APP_ERROR == status:
            message = "Failed to make REST call to generate new authentication token"
            self.error_print(message)
            return self.action_result.set_status(status_code=status, status_message=message)

        if not resp_json.get("access_token", False):
            message = "Response hand invalid or empty access token"
            self.error_print(message)
            return self.action_result.set_status(status_code=status, status_message=message)

        self.tokens[resource].update(token=str(resp_json.get("access_token", '')))

        self.debug_print(f"self.tokens[{resource}]:", self.tokens[resource].parsed)

        return self.action_result.set_status(phantom.APP_SUCCESS, "Authentication successful")

    def _handle_clear_authentication_tokens(self) -> bool:
        self.tokens: dict = {"sentinel": AuthenticationToken(token=""), "loganalytics": AuthenticationToken(token="")}

        self.debug_print("sentinel token cleared:", self.tokens["sentinel"])
        self.debug_print("loganalytics token cleared:", self.tokens["loganalytics"])

        message = "Tokens successfully cleared."
        self.action_result.set_status(status_code=phantom.APP_SUCCESS, status_message=message)
        return self.set_status_save_progress(status_code=phantom.APP_SUCCESS, status_message=message)

    # ---------------------- #
    # Authentication Helpers #
    # ---------------------- #

    def _get_login_uri(self, resource: str) -> str:
        """
        Returns the proper login uri for a given resource

        :param resource: 'sentinel' or 'loganalytics'
        :return: full URI
        """
        if "loganalytics" == resource:
            return f"{self.config.login_uri}/{self.config.tenant_id}/oauth2/token"
        return f"{self.config.login_uri}/{self.config.tenant_id}/oauth2/v2.0/token"

    def _get_scope(self, resource: str) -> str:
        """
        Returns the proper scope for a given resource

        :param resource: 'sentinel' or 'loganalytics'
        :return: resource scope
        """
        if "loganalytics" == resource:
            return self.config.loganalytics_scope
        return self.config.sentinel_scope

    def _requires_token(self, uri: str) -> bool:
        """
        Determines if a URI requires an authentication token

        :param uri: target endpoint
        :return: true if requires token, otherwise false
        """
        return "login" not in uri

    def _get_token(self, uri: str) -> str:
        """
        Gets authentication token required by a given endpoint

        :param uri: target endpoint
        :return: authentication token
        """
        resource = "loganalytics" if "loganalytics" in uri else "sentinel"

        self._authenticate(resource)

        return self.tokens[resource].token

    # ======================== #
    # ACTION HANDLER FUNCTIONS #
    # ======================== #

    # ---------------------- #
    # Primary Action Handler #
    # ---------------------- #

    def handle_action(self, param: dict = None) -> bool:
        # Empty default param definition
        if param is None:
            param = {}

        self.debug_print(f"Using params: {param}")

        if hasattr(self, f"_handle_{self.action_id}"):
            getattr(self, f"_handle_{self.action_id}")(**param)
            return self.set_status_save_progress(self.action_result.get_status(), "Action completed")

        # Missing handler function for action
        message = f"{self.action_id} has no handler function: '_handle_{self.action_id}'"
        self.action_result.set_status(phantom.APP_ERROR, status_message=message)
        return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

    # ------------------ #
    # Connectivity Tests #
    # ------------------ #

    def _handle_verify_authentication_tokens(self, force_refresh: bool = False) -> bool:
        """
        Verifies authentication tokens, or forces a token refresh

        :param force_refresh: force refresh saved tokens
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        # Sentinel
        if not self._authenticate("sentinel", force_refresh):
            message = f"Could not authenticate with sentinel"
            self.error_print(message)
            self.action_result.set_status(phantom.APP_ERROR, status_message=message)
        else:
            message = f"Token [sentinel]: {json.dumps(self.tokens['sentinel'].summary())}"
            self.action_result.set_status(phantom.APP_SUCCESS, message)
            self.action_result.add_data(self.tokens["sentinel"].parsed)

        # Loganalytics
        if not self._authenticate("loganalytics", force_refresh):
            message = f"Could not authenticate with log analytics"
            self.error_print(message)
            self.action_result.set_status(phantom.APP_ERROR, status_message=message)
        else:
            message = f"Token [loganalytics]: {json.dumps(self.tokens['loganalytics'].summary())}"
            self.action_result.set_status(phantom.APP_SUCCESS, message)
            self.action_result.add_data(self.tokens["loganalytics"].parsed)

        # Finish up
        if self.action_result.is_fail():
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Failed to authenticate tokens.")
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Authentication tokens validated.")

    def _handle_test_connectivity(self, force_refresh: bool = False) -> bool:
        """
        Tests connection by attempting to perform basic actions through the APIs

        :param force_refresh: force a token refresh
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        if force_refresh:
            self.debug_print("Refreshing authentication tokens...")
            self._handle_verify_authentication_tokens(force_refresh=force_refresh)
        else:
            self.debug_print("Using cached authentication tokens...")

        # Sentinel
        if not self._handle_list_incidents(**{"limit": 1}):
            message = "Failed to run list incidents API call"
            self.error_print(message)
            self.action_result.set_status(phantom.APP_ERROR, message)

        # Loganalytics

        # Finish up
        if self.action_result.is_fail():
            return self.set_status_save_progress(phantom.APP_ERROR, "Failed connectivity test.")
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Passed connectivity test.")

    # ------------------ #
    # Alert Rule Actions #
    # ------------------ #

    def _handle_create_or_update_action(self, action_id: str, rule_id: str, logic_app_resource_id: str,
                                        trigger_uri: str, etag: str = None) -> bool:
        """
        Creates or updates the action of alert rule.

        :param action_id: Action ID
        :param rule_id: Alert rule ID
        :param logic_app_resource_id: Logic App Resource Id, ../Microsoft.Logic/workflows/{my-workflow-id}.
        :param trigger_uri: Logic App Callback URL for this specific workflow.
        :param etag: Etag of the azure resource
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRules/{rule_id}/"
                            f"actions/{action_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "properties": {
                "logicAppResourceId": logic_app_resource_id,
                "triggerUri": trigger_uri
            }
        }
        if etag:
            data["etag"] = etag

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_action(self, action_id: str, rule_id: str) -> bool:
        """
        Delete the action of alert rule.

        :param action_id: Action ID
        :param rule_id: Alert rule ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRules/{rule_id}/"
                            f"actions/{action_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_action(self, action_id: str, rule_id: str) -> bool:
        """
        Gets the action of alert rule.

        :param action_id: Action ID
        :param rule_id: Alert rule ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRules/{rule_id}/"
                            f"actions/{action_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_actions_by_alert_rule(self, rule_id: str) -> bool:
        """
        Gets all actions of alert rule.

        :param rule_id: Alert rule ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRules/{rule_id}/"
                            f"actions").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # -------------------- #
    # Alert Rule Templates #
    # -------------------- #

    def _handle_get_alert_rule_template(self, alert_rule_template_id: str) -> bool:
        """
        Gets the alert rule template.

        :param alert_rule_template_id: Alert rule template ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRuleTemplates/{alert_rule_template_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_alert_rule_templates(self) -> bool:
        """
        Gets all alert rule templates.

        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRuleTemplates").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ----------- #
    # Alert Rules #
    # ----------- #

    def _handle_create_or_update_alert_rule(self) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        message = ("Just...no."
                   "This is far beyond even worth attempting to make a function for."
                   "https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update")

        self.error_print("Absolutely Not:", message)
        return self.set_status_save_progress(status_code=phantom.APP_ERROR, status_message=message)

    def _handle_delete_alert_rule(self, rule_id: str) -> bool:
        """
        Delete the alert rule.

        :param rule_id: Alert rule ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRules/{rule_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_alert_rule(self, rule_id: str) -> bool:
        """
        Gets the alert rule.

        :param rule_id: Alert rule ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRules/{rule_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_alert_rules(self) -> bool:
        """
        Gets all alert rules.

        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"alertRules").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ---------------- #
    # Automation Rules #
    # ---------------- #

    def _handle_create_or_update_automation_rule(self) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        message = ("Just...no."
                   "This is far beyond even worth attempting to make a function for."
                   "https://learn.microsoft.com/en-us/rest/api/securityinsights/automation-rules/create-or-update")

        self.error_print("Absolutely Not:", message)
        return self.set_status_save_progress(status_code=phantom.APP_ERROR, status_message=message)

    def _handle_delete_automation_rule(self, rule_id: str) -> bool:
        """
        Delete the automation rule.

        :param rule_id: Automation rule ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"automationRules/{rule_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_automation_rule(self, rule_id: str) -> bool:
        """
        Gets the automation rule.

        :param rule_id: Automation rule ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"automationRules/{rule_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_automation_rules(self) -> bool:
        """
        Gets the automation rule.

        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"automationRules").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # --------- #
    # Bookmarks #
    # --------- #

    def _handle_create_or_update_bookmark(self, bookmark_id: str, display_name: str, query: str, etag: str = None,
                                          query_start_time: str = None, query_end_time: str = None) -> bool:
        """
        Creates or updates the bookmark.

        :param bookmark_id: Bookmark ID
        :param display_name: The display name of the bookmark
        :param query: The query of the bookmark
        :param etag: Etag of the azure resource
        :param query_start_time: The start time for the query
        :param query_end_time: The end time for the query
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"bookmarks/{bookmark_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "properties": {
                "displayName": display_name,
                "query": query
            }
        }
        if query_start_time:
            data["properties"]["queryStartTime"] = query_start_time
        if query_end_time:
            data["properties"]["queryEndTime"] = query_end_time
        if etag:
            data["etag"] = etag

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_bookmark(self, bookmark_id: str) -> bool:
        """
        Delete the bookmark.

        :param bookmark_id: Bookmark ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"bookmarks/{bookmark_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_bookmark(self, bookmark_id: str) -> bool:
        """
        Gets a bookmark.

        :param bookmark_id: Bookmark ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"bookmarks/{bookmark_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_bookmarks(self) -> bool:
        """
        Gets all bookmarks.

        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"bookmarks").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ---------------- #
    # Content Packages #
    # ---------------- #

    def _handle_install_content_package(self, package_id: str, content_id: str, content_kind: str,
                                        content_product_id: str, display_name: str, version: str) -> bool:
        """
        Install a package to the workspace.

        :param package_id: Package Id
        :param content_id: The content id of the package
        :param content_kind: The package kind
        :param content_product_id: Unique ID for the content
        :param display_name: The display name of the package
        :param version: The latest version number of the package
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentPackages/{package_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "properties": {
                "contentId": content_id,
                "contentKind": content_kind,
                "contentProductId": content_product_id,
                "displayName": display_name,
                "version": version
            }
        }

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_uninstall_content_package(self, package_id: str) -> bool:

        """
        Uninstall a package from the workspace.

        :param package_id: Package Id
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentPackages/{package_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_content_package(self, package_id: str) -> bool:
        """
        Gets an installed packages by its id.

        :param package_id: Package Id
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentPackages/{package_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_content_packages(self, count_only: bool = False, odata_filter: str = "", order_by: str = "",
                                      search: str = "", skip: int = 0, skip_token: str = "", limit: int = 0) -> bool:
        """
        Gets all installed packages.

        :param count_only: Instructs the server to return only object count without actual data
        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param search: Searches for a substring in the response
        :param skip: Used to skip n elements in the OData query (offset)
        :param skip_token: If a previous response contains a nextLink element, the value of the nextLink element will
            include a skiptoken parameter that specifies a starting point to use for subsequent calls
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentPackages").split(" ", 1)

        params = {"api-version": self.config.api_version}

        if count_only:
            params["$count"] = count_only
        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if search:
            params["$search"] = search
        if skip:
            params["$skip"] = skip
        if skip_token:
            params["$skipToken"] = skip_token
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ----------------- #
    # Content Templates #
    # ----------------- #

    def _handle_delete_content_template(self, template_id: str) -> bool:
        """
        Delete an installed template.

        :param template_id: Template Id
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentTemplates/{template_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_content_template(self, template_id: str) -> bool:
        """
        Gets a template by its identifier.

        :param template_id: Template Id
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentTemplates/{template_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_install_content_template(self, template_id: str, content_id: str, content_kind: str,
                                         content_product_id: str, display_name: str, package_id: str, source_kind: str,
                                         source_name: str, source_id: str, package_version: str,
                                         content_version: str) -> bool:

        """
        Install a template.
    
        :param template_id: Template Id
        :param content_id: Static ID for the content
        :param content_kind: The kind of content the template is for
        :param content_product_id: Unique ID for the content
        :param display_name: The display name of the template
        :param package_id: The package Id contains this template
        :param source_kind: Source type of the content
        :param source_name: Name of the content source.
        :param source_id: ID of the content source
        :param package_version: Version of the package
        :param content_version: Version of the content
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentTemplates/{template_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "properties": {
                "contentId": content_id,
                "contentKind": content_kind,
                "contentProductId": content_product_id,
                "displayName": display_name,
                "packageId": package_id,
                "packageVersion": package_version,
                "source": {
                    "kind": source_kind,
                    "name": source_name,
                    "sourceId": source_id
                },
                "version": content_version
            }
        }

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_content_templates(self, count_only: bool = False, expand: str = "", odata_filter: str = "",
                                       order_by: str = "", search: str = "", skip: int = 0, skip_token: str = "",
                                       limit: int = 0) -> bool:
        """
        Gets all installed templates.

        :param count_only: Instructs the server to return only object count without actual data
        :param expand: Expands the object with optional fiends that are not included by default
        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param search: Searches for a substring in the response
        :param skip: Used to skip n elements in the OData query (offset)
        :param skip_token: If a previous response contains a nextLink element, the value of the nextLink element will
            include a skiptoken parameter that specifies a starting point to use for subsequent calls
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentTemplates").split(" ", 1)

        params = {"api-version": self.config.api_version}

        if count_only:
            params["$count"] = count_only
        if expand:
            params["$expand"] = expand
        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if search:
            params["$search"] = search
        if skip:
            params["$skip"] = skip
        if skip_token:
            params["$skipToken"] = skip_token
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # --------------- #
    # Data Connectors #
    # --------------- #

    def _handle_create_or_update_data_connector(self) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        message = ("Just...no."
                   "This is far beyond even worth attempting to make a function for."
                   "https://learn.microsoft.com/en-us/rest/api/securityinsights/data-connectors/create-or-update")

        self.error_print("Absolutely Not:", message)
        return self.set_status_save_progress(status_code=phantom.APP_ERROR, status_message=message)

    def _handle_delete_data_connector(self, data_connector_id: str) -> bool:
        """
        Delete the data connector.

        :param data_connector_id: Connector ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"dataConnectors/{data_connector_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_data_connector(self, data_connector_id: str) -> bool:
        """
        Gets a data connector.

        :param data_connector_id: Connector ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"dataConnectors/{data_connector_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_data_connectors(self) -> bool:
        """
        Gets all data connectors.

        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"dataConnectors").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # --------------- #
    # Entity Playbook #
    # --------------- #

    def _handle_run_playbook_on_entity(self, entity_id: str, logic_apps_resource_id: str,
                                       incident_arm_id: str = "") -> bool:
        """
        Triggers playbook on a specific entity.

        :param entity_id: Entity ID
        :param logic_apps_resource_id: The resource id of the playbook resource
        :param incident_arm_id: The incident id to associate the entity with
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"POST {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"entities/{entity_id}/"
                            f"runPlaybook").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "logicAppsResourceId": logic_apps_resource_id,
            "tenantId": self.config.tenant_id
        }
        if incident_arm_id:
            data["incidentArmId"] = incident_arm_id

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ----------------- #
    # Incident Comments #
    # ----------------- #

    def _handle_create_or_update_incident_comment(self, incident_id: str, comment_id: str,
                                                  comment_message: str) -> bool:
        """
        Creates or updates a comment for a given incident.

        :param incident_id: Incident ID
        :param comment_id: Incident comment ID
        :param comment_message: The comment message
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"comments/{comment_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {"properties": {"message": comment_message}}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident_comment(self, incident_id: str, comment_id: str) -> bool:
        """
        Deletes a comment for a given incident.

        :param incident_id: Incident ID
        :param comment_id: Incident comment ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"comments/{comment_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident_comment(self, incident_id: str, comment_id: str) -> bool:
        """
        Deletes a comment for a given incident.

        :param incident_id: Incident ID
        :param comment_id: Incident comment ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"comments/{comment_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_comments(self, incident_id: str, odata_filter: str = "", order_by: str = "",
                                       skip_token: str = "", limit: int = 0) -> bool:
        """
        Gets all comments for a given incident.

        :param incident_id: Incident ID
        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param skip_token: If a previous response contains a nextLink element, the value of the nextLink element will
            include a skiptoken parameter that specifies a starting point to use for subsequent calls
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"comments").split(" ", 1)

        params = {"api-version": self.config.api_version}

        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if skip_token:
            params["$skipToken"] = skip_token
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ------------------ #
    # Incident Relations #
    # ------------------ #

    def _handle_create_or_update_incident_relation(self, incident_id: str, relation_name: str,
                                                   related_resource_id: str) -> bool:
        """
        Creates or updates a relation for a given incident.

        :param incident_id: Incident ID
        :param relation_name: Relation Name
        :param related_resource_id: The resource ID of the related resource
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"relations/{relation_name}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {"properties": {"relatedResourceId": related_resource_id}}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident_relation(self, incident_id: str, relation_name: str) -> bool:
        """
        Deletes a relation for a given incident.

        :param incident_id: Incident ID
        :param relation_name: Relation Name
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"relations/{relation_name}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident_relation(self, incident_id: str, relation_name: str) -> bool:
        """
        Gets a relation for a given incident.

        :param incident_id: Incident ID
        :param relation_name: Relation Name
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"relations/{relation_name}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_relations(self, incident_id: str, odata_filter: str = "", order_by: str = "",
                                        skip_token: str = "", limit: int = 0) -> bool:
        """
        Gets all relations for a given incident.

        :param incident_id: Incident ID
        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param skip_token: If a previous response contains a nextLink element, the value of the nextLink element will
            include a skiptoken parameter that specifies a starting point to use for subsequent calls
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"relations").split(" ", 1)

        params = {"api-version": self.config.api_version}
        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if skip_token:
            params["$skipToken"] = skip_token
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # -------------- #
    # Incident Tasks #
    # -------------- #

    def _handle_create_or_update_incident_task(self, incident_id: str, task_id: str, task_status: str,
                                               task_title: str) -> bool:
        """
        Creates or updates the incident task.

        :param incident_id: Incident ID
        :param task_id: Incident task ID
        :param task_status: The status of the task
        :param task_title: The title of the task
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"tasks/{task_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "properties": {
                "status": task_status,
                "title": task_title
            }
        }

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident_task(self, incident_id: str, task_id: str) -> bool:
        """
        Delete the incident task.

        :param incident_id: Incident ID
        :param task_id: Incident task ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"tasks/{task_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident_task(self, incident_id: str, task_id: str) -> bool:
        """
        Gets an incident task.

        :param incident_id: Incident ID
        :param task_id: Incident task ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"tasks/{task_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_tasks(self, incident_id: str) -> bool:
        """
        Gets all incident tasks.

        :param incident_id: Incident ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/"
                            f"tasks").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # --------- #
    # Incidents #
    # --------- #

    def _handle_run_playbook_on_incident(self, incident_id: str, logic_app_resource_id: str) -> bool:
        """
        Triggers playbook on a specific incident.

        :param incident_id: Incident ID
        :param logic_app_resource_id: The resource id of the playbook resource
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"POST {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/runPlaybook").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "logicAppsResourceId": logic_app_resource_id,
            "tenantId": self.config.tenant_id
        }

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_create_or_update_incident(self, incident_id: str, severity: str, status: str, title: str) -> bool:
        """
        Creates or updates an incident.

        :param incident_id: Incident ID
        :param severity: The severity of the incident
        :param status: The status of the incident
        :param title: The title of the incident
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "properties": {
                "severity": severity,
                "status": status,
                "title": title

            }
        }

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident(self, incident_id: str) -> bool:
        """
        Deletes a given incident.

        :param incident_id: Incident ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident(self, incident_id: str) -> bool:
        """
        Gets a given incident.

        :param incident_id: Incident ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incidents(self, odata_filter: str = "", order_by: str = "", skip_token: str = "",
                               limit: int = 0) -> bool:
        """
        Gets all incidents.

        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param skip_token: If a previous response contains a nextLink element, the value of the nextLink element will
            include a skiptoken parameter that specifies a starting point to use for subsequent calls
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents").split(" ", 1)

        params = {"api-version": self.config.api_version}
        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if skip_token:
            params["$skipToken"] = skip_token
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_alerts(self, incident_id: str) -> bool:
        """
        Gets all alerts for an incident.

        :param incident_id: Incident ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"POST {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/alerts").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_bookmarks(self, incident_id: str) -> bool:
        """
        Gets all bookmarks for an incident.

        :param incident_id: Incident ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"POST {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/bookmarks").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_entities(self, incident_id: str) -> bool:
        """
        Gets all entities for an incident.

        :param incident_id: Incident ID
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"POST {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"incidents/{incident_id}/entities").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # -------- #
    # Metadata #
    # -------- #

    def _handle_create_metadata(self, metadata_name: str, metadata_kind: str, parent_id: str) -> bool:
        """
        Create a Metadata.

        :param metadata_name: The Metadata name
        :param metadata_kind: The kind of content the metadata is for
        :param parent_id: Full parent resource ID of the content item the metadata is for
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"PUT {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"metadata/{metadata_name}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {
            "properties": {
                "kind": metadata_kind,
                "parentId": parent_id
            }
        }

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_metadata(self, metadata_name: str) -> bool:
        """
        Delete a Metadata.

        :param metadata_name: The Metadata name
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"DELETE {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"metadata/{metadata_name}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_metadata(self, metadata_name: str) -> bool:
        """
        Get a Metadata.

        :param metadata_name: The Metadata name
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"metadata/{metadata_name}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_metadata(self, odata_filter: str = "", order_by: str = "", skip: int = 0, limit: int = 0) -> bool:
        """
        List of all metadata.

        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param skip: Used to skip n elements in the OData query (offset)
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"metadata").split(" ", 1)

        params = {"api-version": self.config.api_version}
        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if skip:
            params["$skip"] = skip
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_update_metadata(self) -> bool:
        """
        Update an existing Metadata.

        :return: False
        """
        self.save_progress(f"In action handler for {self.action_id}")

        message = ("Just...no."
                   "This is far beyond even worth attempting to make a function for."
                   "https://learn.microsoft.com/en-us/rest/api/securityinsights/metadata/update")

        self.error_print("Absolutely Not:", message)
        return self.set_status_save_progress(status_code=phantom.APP_ERROR, status_message=message)

    # ---------- #
    # Operations #
    # ---------- #

    def _handle_list_operations(self) -> bool:
        """
        Lists all operations available Azure Security Insights Resource Provider.

        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"operations").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ---------------- #
    # Product Packages #
    # ---------------- #

    def _handle_get_product_package(self, package_id: str) -> bool:
        """
        Gets a package by its identifier from the catalog.

        :param package_id: Package Id
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentProductPackages/{package_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_product_packages(self, odata_filter: str = "", order_by: str = "", skip_token: str = "",
                                      limit: int = 0) -> bool:
        """
        Gets all packages from the catalog. Expandable properties:

        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param skip_token: If a previous response contains a nextLink element, the value of the nextLink element will
            include a skiptoken parameter that specifies a starting point to use for subsequent calls
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentProductPackages").split(" ", 1)

        params = {"api-version": self.config.api_version}
        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if skip_token:
            params["$skipToken"] = skip_token
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ----------------- #
    # Product Templates #
    # ----------------- #

    def _handle_get_product_template(self, template_id: str) -> bool:
        """
        Gets a template by its identifier.

        :param template_id: Template Id
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentproducttemplates/{template_id}").split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_product_templates(self, count_only: bool = False, odata_filter: str = "", order_by: str = "",
                                       search: str = "", skip: int = 0, skip_token: str = "", limit: int = 0) -> bool:
        """
        Gets all templates in the catalog.

        :param count_only: Instructs the server to return only object count without actual data
        :param odata_filter: Filters the results, based on a Boolean condition
        :param order_by: Sorts the results
        :param search: Searches for a substring in the response
        :param skip: Used to skip n elements in the OData query (offset)
        :param skip_token: If a previous response contains a nextLink element, the value of the nextLink element will
            include a skiptoken parameter that specifies a starting point to use for subsequent calls
        :param limit: Returns only the first n results
        :return: status
        """
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = (f"GET {self.tokens['sentinel'].endpoint}/"
                            f"subscriptions/{self.config.subscription_id}/"
                            f"resourceGroups/{self.config.resource_group_name}/"
                            f"providers/Microsoft.OperationalInsights/"
                            f"workspaces/{self.config.workspace_name}/"
                            f"providers/Microsoft.SecurityInsights/"
                            f"contentProductTemplates").split(" ", 1)

        params = {"api-version": self.config.api_version}

        if count_only:
            params["$count"] = count_only
        if odata_filter:
            params["$filter"] = odata_filter
        if order_by:
            params["$orderby"] = order_by
        if search:
            params["$search"] = search
        if skip:
            params["$skip"] = skip
        if skip_token:
            params["$skipToken"] = skip_token
        if limit:
            params["$top"] = limit

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ---------------- #
    # Machine Learning #
    # ---------------- #

    def _handle_create_or_update_machine_learning_analytics_settings(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_machine_learning_analytics_settings(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_machine_learning_analytics_settings(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_machine_learning_analytics_settings(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ---------- #
    # Onboarding #
    # ---------- #

    def _handle_create_sentinel_onboarding_state(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_sentinel_onboarding_state(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_sentinel_onboarding_state(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_sentinel_onboarding_state(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # -------------- #
    # Source Control #
    # -------------- #

    def _handle_list_source_control_repositories(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_create_source_control(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_source_control(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_source_control(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_source_control(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ------------------------------ #
    # Threat Intelligence Indicators #
    # ------------------------------ #

    def _handle_append_tags_to_threat_intelligence_indicator(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_create_threat_intelligence_indicator(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_update_threat_intelligence_indicator(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_threat_intelligence_indicator(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_threat_intelligence_indicator(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_query_threat_intelligence_indicators(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_replace_threat_intelligence_indicator_tags(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_threat_intelligence_indicator_metrics(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # --------------- #
    # Watchlist Items #
    # --------------- #

    def _handle_create_or_update_watchlist_item(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_watchlist_item(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_watchlist_item(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_watchlist_items(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_create_or_update_watchlist(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    # ---------- #
    # Watchlists #
    # ---------- #

    def _handle_delete_watchlist(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_watchlist(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_watchlists(self, param) -> bool:
        """"""
        self.save_progress(f"In action handler for {self.action_id}")

        method, endpoint = f"full_endpoint_uri_goes_here".split(" ", 1)

        params = {"api-version": self.config.api_version}

        data = {}

        status, response_data = self._make_rest_call(endpoint=endpoint, params=params, data=data, method=method)

        if not status:
            message = f"Action failed"
            return self.set_status_save_progress(status_code=status, status_message=message)

        self.action_result.add_data(response_data)

        return True

    def initialize(self):
        # Load the state in initialize, use it to store data that needs to be accessed across actions
        self.state = self.load_state()

        # Parse the asset configuration and use defaults as necessary
        self.config = SettingsParser(settings=self.get_config(), defaults=self.config_defaults)
        self.debug_print("self.config.values:", self.config.values)

        # Load token from state and parse
        if self.state.get("tokens", False):
            self.tokens["sentinel"].token = self.state["tokens"]["sentinel"]
            self.debug_print("sentinel token:", self.tokens["sentinel"].summary())

            self.tokens["loganalytics"].token = self.state["tokens"]["loganalytics"]
            self.debug_print("loganalytics token:", self.tokens["loganalytics"].summary())

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save raw tokens since AuthenticationToken is not json serializable
        self.state["tokens"]["sentinel"] = self.tokens["sentinel"].token
        self.state["tokens"]["loganalytics"] = self.tokens["loganalytics"].token

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self.state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SentinelConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = phantom.requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = phantom.requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SentinelConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
