# -*- coding: utf-8 -*-
"""VirusTotal enrichment module."""
import json
from pathlib import Path

import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .builder import VirusTotalBuilder
from .client import VirusTotalClient, VirusTotalGraphClient
from .indicator_config import IndicatorConfig


class VirusTotalConnector:
    """VirusTotal connector."""

    _SOURCE_NAME = "VirusTotal"
    _API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        token = get_config_variable("VIRUSTOTAL_TOKEN", ["virustotal", "token"], config)
        self.max_tlp = get_config_variable(
            "VIRUSTOTAL_MAX_TLP", ["virustotal", "max_tlp"], config
        )
        self.author = stix2.Identity(
            name=self._SOURCE_NAME,
            identity_class="Organization",
            description="VirusTotal",
            confidence=self.helper.connect_confidence_level,
        )

        file_relations = get_config_variable(
            "VIRUSTOTAL_FILE_RELATIONS",
            ["virustotal", "file_relations"],
            config,
        )
        ip_relations = get_config_variable(
            "VIRUSTOTAL_IP_RELATIONS",
            ["virustotal", "ip_relations"],
            config,
        )
        url_relations = get_config_variable(
            "VIRUSTOTAL_URL_RELATIONS",
            ["virustotal", "url_relations"],
            config,
        )
        domain_relations = get_config_variable(
            "VIRUSTOTAL_DOMAIN_RELATIONS",
            ["virustotal", "domain_relations"],
            config,
        )

        self.client = VirusTotalClient(self.helper, self._API_URL, token,file_relations,ip_relations,url_relations,domain_relations)
        
        
        
        # Cache to store YARA rulesets.
        self.yara_cache = {}

        self.bundle = [self.author]

        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            True,
        )
        # File/Artifact specific settings
        self.file_create_note_full_report = get_config_variable(
            "VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT",
            ["virustotal", "file_create_note_full_report"],
            config,
        )
        self.file_indicator_config = IndicatorConfig.load_indicator_config(
            config, "FILE"
        )

        # IP specific settings
        self.ip_indicator_config = IndicatorConfig.load_indicator_config(config, "IP")

        # Domain specific settings
        self.domain_indicator_config = IndicatorConfig.load_indicator_config(
            config, "DOMAIN"
        )

        # Url specific settings
        self.url_indicator_config = IndicatorConfig.load_indicator_config(config, "URL")

    def _retrieve_yara_ruleset(self, ruleset_id: str) -> dict:
        """
        Retrieve yara ruleset.

        If the yara is not in the cache, make an API call.

        Returns
        -------
        dict
            YARA ruleset object.
        """
        self.helper.log_debug(f"[VirusTotal] Retrieving ruleset {ruleset_id}")
        if ruleset_id in self.yara_cache:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from cache.")
            ruleset = self.yara_cache[ruleset_id]
        else:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from API.")
            ruleset = self.client.get_yara_ruleset(ruleset_id)
            self.yara_cache[ruleset_id] = ruleset
        return ruleset

    def run_test(self, observable):
        
        json_data = self.client.get_file_info(observable["observable_value"])
        
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")
        builder = VirusTotalBuilder(
            self.helper, self.author, None, json_data["data"]
        )
        builder.set_observable(observable)
        builder.create_indicator_based_on(
            self.file_indicator_config,
            f"""[file:hashes.'SHA-256' = '{json_data["data"]["attributes"]["sha256"]}']""",
        )

        self.process_file_graph(builder)
        if self.file_create_note_full_report:
            builder.create_note(
                "VirusTotal Report", f"```\n{json.dumps(json_data, indent=2)}\n```"
            )
        builder.create_report()
        return builder.send_bundle()

    def _process_file(self, observable):
        
        json_data = self.client.get_file_info(observable["observable_value"])
        
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")
        
      
        
        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )
        
        
        builder.update_hashes()

        # Set the size and names (main and additional)
        if observable["entity_type"] == "StixFile":
            builder.update_size()

        builder.update_names(
            observable["entity_type"] == "StixFile"
            and (observable["name"] is None or len(observable["name"]) == 0)
        )

        builder.create_indicator_based_on(
            self.file_indicator_config,
            f"""[file:hashes.'SHA-256' = '{json_data["data"]["attributes"]["sha256"]}']""",
        )

        # Create labels from tags
        builder.update_labels()

        # Add YARA rules (only if a rule is given).
        for yara in json_data["data"]["attributes"].get(
            "crowdsourced_yara_results", []
        ):
            ruleset = self._retrieve_yara_ruleset(
                yara.get("ruleset_id", "No ruleset id provided")
            )
            builder.create_yara(
                yara,
                ruleset,
                json_data.get("creation_date", None),
            )

 
        self.process_file_graph(builder)
        
        # Create a Note with the full report
        if self.file_create_note_full_report:
            builder.create_note(
                "VirusTotal Report", f"```\n{json.dumps(json_data, indent=2)}\n```"
            )
        
        builder.create_report()

        return builder.send_bundle()

    def process_file_graph(self,builder):
        #builder.match_sigma_rules()
        malware_id = builder.create_malware()
        
        self.process_behaviours(builder,malware_id)
        
        relations=builder.get_relations()
        
        #self.process_linked_ip_addresses(builder,relations,malware_id)
        #self.process_linked_urls(builder,relations,malware_id)
        #self.process_linked_domains(builder,relations,malware_id)
        #self.process_linked_files(builder,relations,malware_id)
    
    def process_behaviours(self,builder,malware_id):
        behaviours_url=builder.get_behaviours_url()
        if(behaviours_url):
            behaviours_data = self.client.get_file_behaviours(behaviours_url)
            for behaviour in behaviours_data["data"]:
                if len(behaviour["relationships"]["attack_techniques"]["data"])>0:
                    for technique in behaviour["relationships"]["attack_techniques"]["data"]:
                        builder.process_technique(technique,malware_id)
                self.process_behaviour(behaviour["attributes"],builder,malware_id)
            
        #print(len(builder.get_bundle()))
    
    def process_behaviour(self,behaviour_attributes,builder,malware_id):
        if("mutexes_created" in behaviour_attributes):                                                    
            mutexes_created=behaviour_attributes["mutexes_created"]
            for mutex in mutexes_created:
                builder.create_mutex(mutex,malware_id)
        if("registry_keys_deleted" in behaviour_attributes):                                                            
            registry_keys_deleted=behaviour_attributes["registry_keys_deleted"]
            for key in registry_keys_deleted:
                builder.create_window_registry_key(key,malware_id)
        if("processes_injected" in behaviour_attributes):                                                                   
            processes_created=behaviour_attributes["processes_injected"]
            for process in processes_created:
                builder.create_process(process,malware_id)

    def process_linked_files(self,parent_builder,data_relations,malware_id):
        relations_map={"drops": ["dropped_files"],"part-of": ["carbonblack_parents","compressed_parents","execution_parents","overlay_parents","pe_resource_parents"],"related-to": ["carbonblack_children","overlay_children","pe_resource_children"]}
        for (relationship,relation_names) in relations_map.items():
            for relation_name in relation_names:
                if relation_name in data_relations.keys():
                    relation_datas = data_relations[relation_name]
                    for file_data in relation_datas["data"]:
                        file_id=self.process_linked_file(parent_builder, file_data["id"])
                        if(file_id):
                            parent_builder.link_malware_with_related_observable(malware_id,file_id,relation_name,relationship)
                            
                    
                    
    def process_linked_file(self,parent_builder, file_id):
        json_data = self.client.get_file_info(file_id)
        assert json_data
        if "error" in json_data:
            return None
            #raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, None, json_data["data"]
        )
        
        observable=builder.get_opencti_file(json_data["data"]["attributes"]["sha256"])
        if(observable):
            builder.set_observable(observable)
            builder.update_hashes()
            builder.update_size()
            builder.update_names(
                (observable["name"] is None or len(observable["name"]) == 0)
            )

            builder.create_indicator_based_on(
                self.file_indicator_config,
                f"""[file:hashes.'SHA-256' = '{json_data["data"]["attributes"]["sha256"]}']""",
            )
            # Create labels from tags
            builder.update_labels()
            file_id=observable["standard_id"]
        else:
            file_id = builder.create_file().id    
        
        parent_builder.collect_bundle_content(builder.get_bundle())
        return file_id
       
    def process_linked_ip_addresses(self,parent_builder,data_relations,malware_id):
        relations_map={"communicates-with": ["contacted_ips"],"related-to": ["embedded_ips"],"originates-from": ["itw_ips"]}
        for (relationship,relation_names) in relations_map.items():
            for relation_name in relation_names:
                if relation_name in data_relations.keys():
                    relation_datas = data_relations[relation_name]
                    for ip_data in relation_datas["data"]:
                        ip_id=self.process_linked_ip(parent_builder, ip_data["id"])
                        if(ip_id):
                            parent_builder.link_malware_with_related_observable(malware_id,ip_id,relation_name,relationship)

    def process_linked_ip(self,parent_builder, ip_value):
        json_data = self.client.get_ip_info(ip_value)
        assert json_data
        if "error" in json_data:
            return None#raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, None, json_data["data"]
        )
        ip_address_id = builder.create_ip(ip_value).id
        observable={"standard_id": ip_address_id,"observable_value": ip_value}
        builder.set_observable(observable)
        builder.create_asn_belongs_to()
        builder.create_location_located_at()

        builder.create_indicator_based_on(
            self.ip_indicator_config,
            f"""[ipv4-addr:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        parent_builder.collect_bundle_content(builder.get_bundle())
        return ip_address_id

    def process_linked_domains(self,parent_builder,data_relations,malware_id):
        relations_map={"communicates-with": ["contacted_domains"],"related-to": ["embedded_domains"],"originates-from": ["itw_domains"]}
        for (relationship,relation_names) in relations_map.items():
            for relation_name in relation_names:
                if relation_name in data_relations.keys():
                    relation_datas = data_relations[relation_name]
                    for domain_data in relation_datas["data"]:
                        domain_id=self.process_linked_domain(parent_builder, domain_data["id"])
                        if(domain_id):
                            parent_builder.link_malware_with_related_observable(malware_id,domain_id,relation_name,relationship)
                          

    def process_linked_domain(self,parent_builder, domain_value):
        json_data = self.client.get_domain_info(domain_value)
        assert json_data
        if "error" in json_data:
            return None#raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, None, json_data["data"]
        )
        domain_id = builder.create_domain(domain_value).id
        observable={"standard_id": domain_id,"observable_value": domain_value}
        builder.set_observable(observable)
       
        # Create IPv4 address observables for each A record
        # and a Relationship between them and the observable.
        for ip in [
            r["value"]
            for r in json_data["data"]["attributes"]["last_dns_records"]
            if r["type"] == "A"
        ]:
            self.helper.log_debug(
                f'[VirusTotal] adding ip {ip} to domain {observable["observable_value"]}'
            )
            builder.create_ip_resolves_to(ip)

        builder.create_indicator_based_on(
            self.domain_indicator_config,
            f"""[domain-name:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        parent_builder.collect_bundle_content(builder.get_bundle())
        return domain_id


    def process_linked_urls(self,parent_builder,data_relations,malware_id):
        relations_map={"communicates-with": ["contacted_urls"],"related-to": ["embedded_urls"],"originates-from": ["itw_urls"]}
        for (relationship,relation_names) in relations_map.items():
            for relation_name in relation_names:
                if relation_name in data_relations.keys():
                    relation_datas = data_relations[relation_name]
                    for url_data in relation_datas["data"]:
                        url_id=self.process_linked_url(parent_builder, url_data["id"])
                        if(url_id):
                            parent_builder.link_malware_with_related_observable(malware_id,url_id,relation_name,relationship)


    def process_linked_url(self,parent_builder, url_value):
        json_data = self.client.get_url_info(url_value)
        assert json_data
        if "error" in json_data:
            return None#raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, None, json_data["data"]
        )
        url_id = builder.create_url(url_value).id
        observable={"standard_id": url_id,"observable_value": url_value}
        builder.set_observable(observable)
       
        builder.create_indicator_based_on(
            self.ip_indicator_config,
            f"""[url:value = '{observable["observable_value"]}']""",        )
        builder.create_notes()
        parent_builder.collect_bundle_content(builder.get_bundle())
        return url_id
         
    def _process_ip(self, observable):
        json_data = self.client.get_ip_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )

        builder.create_asn_belongs_to()
        builder.create_location_located_at()

        builder.create_indicator_based_on(
            self.ip_indicator_config,
            f"""[ipv4-addr:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        return builder.send_bundle()

    def _process_domain(self, observable):
        json_data = self.client.get_domain_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )

        # Create IPv4 address observables for each A record
        # and a Relationship between them and the observable.
        for ip in [
            r["value"]
            for r in json_data["data"]["attributes"]["last_dns_records"]
            if r["type"] == "A"
        ]:
            self.helper.log_debug(
                f'[VirusTotal] adding ip {ip} to domain {observable["observable_value"]}'
            )
            builder.create_ip_resolves_to(ip)

        builder.create_indicator_based_on(
            self.domain_indicator_config,
            f"""[domain-name:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        return builder.send_bundle()

    def _process_url(self, observable):
        json_data = self.client.get_url_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            self.helper, self.author, observable, json_data["data"]
        )

        builder.create_indicator_based_on(
            self.ip_indicator_config,
            f"""[url:value = '{observable["observable_value"]}']""",
        )
        builder.create_notes()
        return builder.send_bundle()

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, "
                "check the group of the connector user)"
            )

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        self.helper.log_debug(
            f"[VirusTotal] starting enrichment of observable: {observable}"
        )
        match observable["entity_type"]:
            case "StixFile" | "Artifact":
                return self._process_file(observable)
            case "IPv4-Addr":
                return self._process_ip(observable)
            case "Domain-Name":
                return self._process_domain(observable)
            case "Url":
                return self._process_url(observable)
            case _:
                raise ValueError(
                    f'{observable["entity_type"]} is not a supported entity type.'
                )

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
