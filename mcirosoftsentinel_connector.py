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
    def action_result(self) -> ActionResult:
        if not self._action_result:
            self._action_result = self.add_action_result(ActionResult({'action started': self.action_id}))
        return self._action_result

    _action_result: ActionResult = None

    @property
    def tld(self) -> str:
        if not self.config:
            return ""
        return self.config.login_uri.split(".")[-1]

    def __init__(self):

        # Call the BaseConnectors init first
        super(SentinelConnector, self).__init__()

        self._state = None

        self._tenant_id = None
        self._subscription_id = None
        self._client_id = None
        self._client_secret = None
        self._workspace_name = None
        self._resource_group_name = None
        self._login_url = None

        # New version class variables
        self.state = None
        self.tokens: dict = {"sentinel": AuthenticationToken(token=""), "loganalytics": AuthenticationToken(token="")}
        self.config: SettingsParser = None
        self.params: SettingsParser = None
        self.response = None
        self.response_json = None

    #
    # REST
    #

    # Primary REST Caller

    def _make_rest_call(self, endpoint: str, method: str = "get", verify: bool = False, **kwargs) -> RetVal:
        # Make sure REST method exists in requests
        try:
            request_func = getattr(phantom.requests, method)
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
            self.debug_print(f"Making REST call to {endpoint}")
            return self._process_response(request_func(endpoint, verify=verify, **kwargs))
        except Exception as e:
            message = f"REST call Exception: {parse_exception_message(e)}"
            self.error_print(message)
            self.action_result.set_status(phantom.APP_ERROR, message)
            return RetVal(self.set_status_save_progress(phantom.APP_ERROR, message))

    # Response Processors

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

    def _process_json_response(self, response: Response = None) -> RetVal:
        """
        Attempts to parse a JSON content response.

        :param response: request response object
        :return: [status, JSON|message]
        """
        try:
            resp_json = response.json()
        except Exception as e:
            message = f"Unable to parse JSON response. Error: {parse_exception_message(e)}"
            self.error_print(message)
            return RetVal(self.action_result.set_status(phantom.APP_ERROR, message), message)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

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

    #
    # AUTHENTICATION
    #

    # Authentication Token Getter

    def _authenticate(self, resource: str = "sentinel", force_refresh: bool = False) -> bool:
        """
        Checks for an authentication token for a given resource, and if none exist, generates a new one

        :param resource: the resource to authenticate with, 'sentinel' or 'loganalytics'
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

        # Prepare to request a new token
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": self.config.login_scope,
            "grant_type": "client_credentials"
        }

        uri_endpoint = "/oauth2/token" if "loganalytics" == resource else f"/oauth2/v2.0/token"

        ret_val, resp_json = self._make_rest_call(
            endpoint=f"{self.config.login_uri}/{self.config.tenant_id}{uri_endpoint}",
            headers=headers,
            data=body,
            verify=False
        )

        if phantom.APP_ERROR == ret_val:
            message = "Failed to make REST call to generate new authentication token"
            self.error_print(message)
            return self.action_result.set_status(phantom.APP_ERROR, message)

        if not resp_json.get("access_token", False):
            message = "Response hand invalid or empty access token"
            self.error_print(message)
            return self.action_result.set_status(phantom.APP_ERROR, message)

        self.tokens[resource].update(token=str(resp_json.get("access_token", '')))

        summary = self.tokens[resource].summary()
        message = (f"[{resource}]: expires on {summary['expires_on']} ({summary['expires_in']})")
        self.debug_print("Authentication successful", message)

        return self.action_result.set_status(phantom.APP_SUCCESS, message)

    # Authentication Helpers

    def _requires_token(self, uri: str) -> bool:
        """
        Determines if a URI points to an endpoint requiring an authentication token

        :param uri: target endpoint
        :return: true if requires token, otherwise false
        """
        return "management.azure" in uri or "api.loganalytics.azure" in uri

    def _get_token(self, uri: str) -> str:
        """
        Gets authentication token required by a given endpoint

        :param uri: target endpoint
        :return: authentication token
        """
        if "management.azure" in uri:
            return self.tokens["sentinel"].token
        return self.tokens["loganalytics"].token

    #
    # ACTIONS
    #

    def handle_action(self, param: dict = None) -> bool:
        # Empty default param definition
        if param is None:
            param = {}

        if hasattr(self, f"_handle_{self.action_id}"):
            getattr(self, f"_handle_{self.action_id}")(**param)
            return self.set_status_save_progress(self.action_result.get_status(), "Action completed")

        # Missing handler function for action
        message = f"{self.action_id} has no handler function: '_handle_{self.action_id}'"
        self.action_result.set_status(phantom.APP_ERROR, status_message=message)
        return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

    # Connectivity

    def _handle_verify_authentication_tokens(self, force_refresh: bool = False) -> bool:
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

    def _handle_test_connectivity(self) -> bool:
        """
        Tests connection by attempting to perform basic actions through the APIs

        :param param: dictionary of parameters
            - force_refresh [bool]: if set to True, any existing tokens are removed and reganerated
        :return: bool
        """
        self.save_progress(f"In action handler for {self.action_id}")

        # Sentinel
        if not self._handle_list_incidents({"top": 1}):
            message = "Failed to run list incidents API call"
            self.error_print(message)
            self.action_result.set_status(phantom.APP_ERROR, message)

        # Loganalytics

        # Finish up
        if self.action_result.is_fail():
            return self.set_status_save_progress(phantom.APP_ERROR, "Failed connectivity test.")
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Passed connectivity test.")

    # Alert Rules

    def _handle_create_or_update_alert_rule(self, alert_rule_id: str, action_id: str, logic_app_resource_id: str,
                                            trigger_uri: str, etag: str = "") -> bool:
        """
        Creates or updates the action of alert rule.

        :param logic_app_resource_id: Logic App Resource Id
        :param trigger_uri: Logic App Callback URL for this specific workflow.
        :param etag: Etag of the azure resource
        :return: bool
        """
        self.save_progress(f"In action handler for {self.action_id}")

        params = {
            "etag": etag,
            "properties": {
                "triggerUri": trigger_uri,
                "logicAppResourceId": logic_app_resource_id
            }
        }

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{alert_rule_id}/"
                    f"actions/{action_id}?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="PUT", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_alert_rule(self, alert_rule_id: str, action_id: str) -> bool:
        """
        Delete the action of alert rule.

        :param alert_rule_id: Alert rule ID
        :param action_id: Action ID
        :return: bool
        """
        self.save_progress(f"In action handler for {self.action_id}")

        params = {
            "ruleId": alert_rule_id,
            "actionId": action_id
        }

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{alert_rule_id}/"
                    f"actions/{action_id}?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="DELETE", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_alert_rule(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_alert_rules(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Alert Rule Actions

    def _handle_create_or_update_alert_rule_action(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{self.params.rule_id}/"
                    f"actions?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_alert_rule_action(self, alert_rule_id: str, action_id: str) -> bool:
        """
        Delete the action of alert rule.

        :param alert_rule_id: Alert rule ID
        :param action_id: Action ID
        :return: bool
        """
        self.save_progress(f"In action handler for {self.action_id}")

        params = {
            "ruleId": alert_rule_id,
            "actionId": action_id
        }

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{alert_rule_id}/"
                    f"actions/{action_id}?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_alert_rule_action(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{self.params.rule_id}/"
                    f"actions?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_action_by_alert_rule(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{self.params.rule_id}/"
                    f"actions?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Alert Rule Templates

    def _handle_get_alert_rule_template(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{self.params.rule_id}/"
                    f"actions?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_alert_rule_templates(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"alertRules/{self.params.rule_id}/"
                    f"actions?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Automation Rules

    def _handle_create_or_update_automation_rule(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"automationRules/{self.params.rule_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_automation_rule(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"automationRules/{self.params.rule_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_automation_rule(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"automationRules/{self.params.rule_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_automation_rules(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"automationRules/{self.params.rule_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Bookmarks

    def _handle_create_or_update_bookmark(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"bookmarks/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_bookmark(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"bookmarks/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_bookmark(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"bookmarks/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_bookmarks(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"bookmarks/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Content Packages

    def _handle_install_content_package(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"contentPackages/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_uninstall_content_package(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"contentPackages/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Content Templates

    def _handle_list_content_templates(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"contentTemplates/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Data Connectors

    def _handle_create_or_update_data_connector(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"dataConnectors/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_data_connector(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"dataConnectors/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_data_connector(self, param: dict = None) -> bool:
        """

        :param param: dictionary of parameters
            -
        :return:
        """

        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"dataConnectors/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_data_connectors(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"dataConnectors/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Entity Playbook

    def _handle_run_playbook_on_entity(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"entities/{self.params.id}/"
                    f"runPlaybook?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Incident Comments

    def _handle_create_or_update_incident_comment(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"comments/{self.params.comment_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident_comment(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"comments/{self.params.comment_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident_comment(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"comments/{self.params.comment_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_comments(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"comments/{self.params.comment_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Incident Relations

    def _handle_create_or_update_incident_relation(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"relations/{self.params.relation_name}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident_relation(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"relations/{self.params.relation_name}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident_relation(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"relations/{self.params.relation_name}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_relations(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"relations/{self.params.relation_name}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Incident Tasks

    def _handle_create_or_update_incident_task(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"tasks/{self.params.task_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident_task(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"tasks/{self.params.task_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident_task(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"tasks/{self.params.task_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_tasks(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.incident_id}/"
                    f"tasks/{self.params.task_id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Incidents

    def _handle_run_playbook_on_incident(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_create_or_update_incident(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_incident(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_incident(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults: dict = {"id": 0}
        self.params = SettingsParser(settings=param, defaults=defaults)

        if 0 == self.params.id:
            message = f"Invalid incident id proivided: '0'"
            self.action_result.set_status(phantom.APP_ERROR, status_message=message)
            return self.set_status_save_progress(phantom.APP_ERROR, status_message=message)

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents/{self.params.id}?api-version=2024-03-01")

    def _handle_list_incidents(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults: dict = {
            "top": 0,
            "odata_filter": "",
            "api_version": "2023-11-01"
        }
        self.params = SettingsParser(settings=param, defaults=defaults)
        self.action_result.add_debug_data(self.params)

        params = {}
        if self.params.top:
            params["$top"] = self.params.top
        if self.params.odata_filter:
            params["$filter"] = self.params.odata_filter
        if self.params.api_version:
            params["api-version"] = self.params.api_version

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents")

        ret_val, incident_list = self._make_rest_call(
            endpoint=endpoint,
            params=params,
            method="get",
            verify=False
        )

        self.debug_print("ret_val:", ret_val)
        self.debug_print("incident_list:", incident_list)
        self.debug_print("action_result message:", self.action_result.get_message())

        return True

    def _handle_list_incident_alerts(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_bookmarks(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_incident_entities(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"incidents")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Metadata

    def _handle_create_metadata(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"metadata?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_metadata(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"metadata?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_metadata(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"metadata?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_metadata(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"metadata?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_update_metadata(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"metadata?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Operations

    def _handle_list_operations(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"operations?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Product Packages

    def _handle_get_product_package(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"contentProductPackages/{self.config.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_product_packages(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"contentProductPackages?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Product Templates

    def _handle_get_product_template(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"contentProductTemplates/{self.params.id}"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_product_templates(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"contentProductTemplates?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Security Machine Learning

    def _handle_create_or_update_machine_learning_analytics_settings(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"securityMLAnalyticsSettings?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_machine_learning_analytics_settings(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"securityMLAnalyticsSettings?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_machine_learning_analytics_settings(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"securityMLAnalyticsSettings?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_machine_learning_analytics_settings(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"securityMLAnalyticsSettings?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Sentinel Onboarding States

    def _handle_create_sentinel_onboarding_state(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"onboardingStates?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_sentinel_onboarding_state(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"onboardingStates?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_sentinel_onboarding_state(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"onboardingStates?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_sentinel_onboarding_state(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"onboardingStates?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Source Control Repositories

    def _handle_list_source_control_repositories(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"listRepositories?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Source Control

    def _handle_create_source_control(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"sourcecontrols?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_source_control(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"sourcecontrols?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_source_control(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"sourcecontrols?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_source_control(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"sourcecontrols?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Threat Intelligence Indicators

    def _handle_append_tags_to_threat_intelligence_indicator(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_create_threat_intelligence_indicator(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_update_threat_intelligence_indicator(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_threat_intelligence_indicator(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_threat_intelligence_indicator(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_query_threat_intelligence_indicators(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_replace_threat_intelligence_indicator_tags(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Threat Intelligence Indicator Metrics

    def _handle_list_threat_intelligence_indicator_metrics(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"threatIntelligence/main/indicators"
                    f"?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Watchlist Items

    def _handle_create_or_update_watchlist_item(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_watchlist_item(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_watchlist_item(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_watchlist_items(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    # Watchlists

    def _handle_create_or_update_watchlist(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_delete_watchlist(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_get_watchlist(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    def _handle_list_watchlists(self, param: dict = None) -> bool:
        self.save_progress(f"In action handler for {self.action_id}")

        defaults = {}
        self.params = SettingsParser(settings=param, defaults=defaults)

        params = self.params

        endpoint = (f"{self.tokens['sentinel'].endpoint}/"
                    f"subscriptions/{self.config.subscription_id}/"
                    f"resourceGroups/{self.config.resource_group_name}/"
                    f"providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self.config.workspace_name}/"
                    f"providers/Microsoft.SecurityInsights/"
                    f"watchlists?api-version=2024-03-01")

        ret_val, response_data = self._make_rest_call(endpoint=endpoint, params=params, method="get", verify=False)

        self.action_result.add_data(response_data)

        return True

    #
    # PSEUDOSTRUCTS
    #

    def initialize(self):
        # Load the state in initialize, use it to store data that needs to be accessed across actions
        self.state = self.load_state()

        config_default = {
            "login_uri": "https://login.microsoftonline.com",
            "login_scope": "https://management.azure.com/.default",
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "resource_group_name": "target-sentinel-group",
            "workspace_name": "workspace-name-here",
            "workspace_id": "00000000-0000-0000-0000-000000000000",
            "client_id": "00000000-0000-0000-0000-000000000000",
            "client_secret": "(Sup3rS3cr37P455w0rd_goesHERE)",
            "first_run_max_incidents": 1000,
            "start_time_scheduled_poll": "1970-01-01T00:00:00Z",
        }

        # get the asset config
        self.config = SettingsParser(settings=self.get_config(), defaults=config_default)
        self.debug_print("self.config", json.dumps(self.config.values, indent=4))

        # Load token from state and parse
        if self.state.get("tokens", False):
            self.tokens["sentinel"].token = self.state["tokens"]["sentinel"]
            self.tokens["loganalytics"].token = self.state["tokens"]["loganalytics"]
            self.debug_print("self.state['tokens']", self.state["tokens"])
        else:
            self.state["tokens"] = {}
            self.debug_print("self.state:", self.state)

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
