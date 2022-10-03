# -*- coding: utf-8 -*-
"""Virustotal client module."""
import base64
import json
import vt
import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class VirusTotalGraphClient:
    """VirusTotal client."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, token: str
    ) -> None:
        """Initialize Virustotal client."""
        self.helper = helper
        # Drop the ending slash if present.
        self.client=vt.Client(token)
    
    def get_file_info(self, hash):
        """
        Retrieve file information based on the given hash (any hash).

        Parameters
        ----------
        hash256 : str
            Hash of the file to retrieve.

        Returns
        -------
        dict
            File object, see https://developers.virustotal.com/reference/files.
        """
        
        return self.client.get_object("/files/{}?relationships=behaviours,contacted_domains,contacted_ips,contacted_urls,dropped_files,itw_urls,itw_domains,itw_ips,carbonblack_children,carbonblack_parents,compressed_parents,embedded_domains,embedded_ips,embedded_urls,execution_parents,overlay_children,overlay_parents,pcap_children,pcap_parents,pe_resource_children,pe_resource_parents,similar_files,screenshots",hash)


class VirusTotalClient:
    """VirusTotal client."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: str, token: str,file_relations:str,ip_relations:str,url_relations:str,domain_relations:str
    ) -> None:
        """Initialize Virustotal client."""
        self.helper = helper
        # Drop the ending slash if present.
        self.url = base_url[:-1] if base_url[-1] == "/" else base_url
        self.helper.log_info(f"[VirusTotal] URL: {self.url}")
        self.headers = {
            "x-apikey": token,
            "accept": "application/json",
            "content-type": "application/json",
        }
        self.file_relations=file_relations
        self.ip_relations=ip_relations
        self.url_relations=url_relations
        self.domain_relations=domain_relations
        
    def _query(self, url):
        """
        Execute a query to the Virustotal api.
        The authentication is done using the headers with the token given
        during the creation of the client.
        Retries are done if the query fails.
        Parameters
        ----------
        url : str
            Url to query.
        Returns
        -------
        JSON or None
            The result of the query, as JSON or None in case of failure.
        """
        # Configure the adapter for the retry strategy.
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        response = None
        try:
            response = http.get(url, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[VirusTotal] Http error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            self.helper.log_error(f"[VirusTotal] Error connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            self.helper.log_error(f"[VirusTotal] Timeout error: {errt}")
        except requests.exceptions.RequestException as err:
            self.helper.log_error(f"[VirusTotal] Something else happened: {err}")
        except Exception as err:
            self.helper.log_error(f"[VirusTotal] Unknown error {err}")
        try:
            self.helper.log_debug(f"[VirusTotal] data retrieved: {response.json()}")
            return response.json()
        except json.JSONDecodeError as err:
            self.helper.log_error(
                f"[VirusTotal] Error decoding the json: {err} - {response.text}"
            )
            return None
        
    def get_file_info(self, hash):
        """
        Retrieve file information based on the given hash (any hash).

        Parameters
        ----------
        hash256 : str
            Hash of the file to retrieve.

        Returns
        -------
        dict
            File object, see https://developers.virustotal.com/reference/files.
        """
        url = f"{self.url}/files/{hash}"
        
        if(self.file_relations is not None):
            url+="?relationships="+self.file_relations
        #behaviours,contacted_domains,contacted_ips,contacted_urls,dropped_files,itw_urls,itw_domains,itw_ips,carbonblack_children,carbonblack_parents,compressed_parents,embedded_domains,embedded_ips,embedded_urls,execution_parents,overlay_children,overlay_parents,pcap_children,pcap_parents,pe_resource_children,pe_resource_parents,similar_files,screenshots"
        return self._query(url)        
        
    def get_file_behaviours(self,url):
        url+="?relationships=attack_techniques"
        
        return self._query(url)
        
    def get_yara_ruleset(self, ruleset_id) -> dict:
        """
        Retrieve the YARA rules based on the given ruleset id.

        Parameters
        ----------
        ruleset_id : str
            Ruleset id to retrieve.

        Returns
        -------
        dict
            YARA ruleset objects, see https://developers.virustotal.com/reference/yara-rulesets
        """
        url = f"{self.url}/yara_rulesets/{ruleset_id}"
        return self._query(url)

    def get_ip_info(self, ip):
        """
        Retrieve IP report based on the given IP.

        Parameters
        ----------
        ip : str
            IP address.

        Returns
        -------
        dict
            IP address object, see https://developers.virustotal.com/reference/ip-object
        """
        url = f"{self.url}/ip_addresses/{ip}"
        return self._query(url)

    def get_domain_info(self, domain):
        """
        Retrieve Domain report based on the given Domain.

        Parameters
        ----------
        domain : str
            Domain name.

        Returns
        -------
        dict
            Domain Object, see https://developers.virustotal.com/reference/domains-1
        """
        url = f"{self.url}/domains/{domain}"
        return self._query(url)

    def get_url_info(self, url):
        """
        Retrieve URL report based on the given URL.

        Parameters
        ----------
        url : str
            Url.

        Returns
        -------
        dict
            URL Object, see https://developers.virustotal.com/reference/url-object
        """
        url = f"{self.url}/urls/{VirusTotalClient.base64_encode_no_padding(url)}"
        return self._query(url)

    @staticmethod
    def base64_encode_no_padding(contents):
        """
        Base64 encode a string and remove padding.

        Parameters
        ----------
        contents : str
            String to encode.

        Returns
        -------
        str
            Base64 encoded string without padding
        """
        return base64.b64encode(contents.encode()).decode().replace("=", "")
