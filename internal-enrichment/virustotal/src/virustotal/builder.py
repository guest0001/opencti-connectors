# -*- coding: utf-8 -*-
"""VirusTotal builder module."""
import datetime as dt
import time

import json
from typing import Optional

import plyara
import plyara.utils
import stix2
from vt import Object
from pycti import (
    ExternalReference,
    Location,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Report
)

from .indicator_config import IndicatorConfig
from stix2.v21.sdo import Malware, MalwareAnalysis, AttackPattern
from stix2.v21.observables import Process,WindowsRegistryKey,Mutex
from attr import attributes



class VirusTotalBuilder:
    """VirusTotal builder."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        observable: dict,
        data: dict
    ) -> None:
        """Initialize Virustotal builder."""
        self.helper = helper
        self.author = author
        self.bundle = [self.author]
        self.indicators=[]
        self.bundle_objects=[]
        self.observable = observable
        self.attributes = data["attributes"]
        self.relations=None
        if "relationships" in data.keys():
            self.relations=data["relationships"]
            if "behaviours" in self.relations.keys():
                self.behaviours=self.relations["behaviours"]
        
        
        self.score = VirusTotalBuilder._compute_score(
            self.attributes["last_analysis_stats"]
        )

        # Update score of observable.
        if(self.observable is not None):
            self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "x_opencti_score", "value": str(self.score)},
        )
        self.sigma_rules=self.load_sigma_rules()
        # Add the external reference.
        link = self._extract_link(data["links"]["self"])
        if (link is not None) and (self.observable is not None):
            self.helper.log_debug(f"[VirusTotal] adding external reference {link}")
            self.external_reference = self._create_external_reference(
                link,
                self.attributes.get("magic", "VirusTotal Report"),
            )
        else:
            self.external_reference = None
            
        self.malwares=self.load_malwares()
        self.load_attack_techniks()
        
    def load_malwares(self):
        
        malware_query="""query Malwares($malwares_number:Int){

                        malwares(first: $malwares_number){
                          edges{
                            node{
                              standard_id,
                              name,
                              aliases
                            }
                          }
              }
            }
        """
        args={"malwares_number": 2000}
        response=self.helper.api.query(malware_query,args)
        
        malwares={}
        for malware in response["data"]["malwares"]["edges"]:
            id=malware["node"]["standard_id"]
            
            malwares[malware["node"]["name"].lower()]=id
            if(malware["node"]["aliases"]is not None):
                for alias in malware["node"]["aliases"]:
                    malwares[alias.lower()]=id
            
        
        return malwares

    def load_attack_techniks(self):
        
        attacks_query="""query attacks{
                                      attackPatterns(first:2000 orderBy: x_mitre_id){
                                        edges{
                                          node{
                                          x_opencti_stix_ids
                                            x_mitre_id
                                            standard_id
                                            name
                                          }
                                          
                                        }
                                      }
                                    }
        """
        
        response=self.helper.api.query(attacks_query)
        
        self.mitre_attacks_names={}
        self.mitre_attacks={}
        for edge in response["data"]["attackPatterns"]["edges"]:
            if(edge["node"]["x_mitre_id"]):
                mitre_id=edge["node"]["x_mitre_id"].lower()
                self.mitre_attacks[mitre_id.lower()]=edge["node"]["x_opencti_stix_ids"][0]
                self.mitre_attacks_names[mitre_id.lower()]=edge["node"]["name"].lower()    
        

    def process_technique(self,technique,malware_id):
        mitre_id=technique["id"]
        for signature in technique["context_attributes"]["signatures"]:
            severity = signature["severity"]
            desc=signature["description"]
            
            self.create_technique_link(mitre_id, desc, malware_id)
                            

    def create_technique_link(self,mitre_id,tech_desc,malware_id):
        
        if mitre_id and self.mitre_attacks[mitre_id.lower()]:
            
            attack = AttackPattern(id=self.mitre_attacks[mitre_id.lower()],
                                   name=self.mitre_attacks_names[mitre_id.lower()])
            
            relationship = stix2.Relationship(
                relationship_type="uses",
                created_by_ref=self.author,
                source_ref=malware_id,
                target_ref=self.mitre_attacks[mitre_id.lower()],
                confidence=self.helper.connect_confidence_level,
                description=tech_desc,
                allow_custom=True,
                )
            self.bundle+=[attack,relationship]

    def create_mutex(self,mutex,malware_id):
        mutex = Mutex(name=mutex,
                      created_by_ref=self.author.id,
                    confidence=self.helper.connect_confidence_level,
                    labels=["VirusTotal"])
        self.bundle.append(mutex)
        relationship = stix2.Relationship(
            relationship_type="creates",
            created_by_ref=self.author,
            source_ref=malware_id,
            target_ref=mutex.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
            )
        self.bundle+=[relationship]
    def create_window_registry_key(self,win_key,malware_id):
        win_key = WindowsRegistryKey(key=win_key,
                      created_by_ref=self.author.id,
                    confidence=self.helper.connect_confidence_level,
                    labels=["VirusTotal"])
        self.bundle.append(win_key)
        relationship = stix2.Relationship(
            relationship_type="deletes",
            created_by_ref=self.author,
            source_ref=malware_id,
            target_ref=win_key.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
            )
        self.bundle+=[relationship]
    def create_process(self,cwd_process,malware_id):
        process = Process(cwd=cwd_process,
                      created_by_ref=self.author.id,
                    confidence=self.helper.connect_confidence_level,
                    labels=["VirusTotal"])
        self.bundle.append(process)
        relationship = stix2.Relationship(
            relationship_type="injects",
            created_by_ref=self.author,
            source_ref=malware_id,
            target_ref=process.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
            )
        self.bundle+=[relationship]

    def get_behaviours_url(self):
        behaviours_url=None
        if self.behaviours:
            behaviours_url=self.behaviours["links"]["related"]
        return behaviours_url
            
    def process_node(self,node,attacks):
        if(len(node["x_opencti_stix_ids"]) > 0):
            mitre_id=node["x_mitre_id"].lower()
            attacks[mitre_id]=node["x_opencti_stix_ids"][0]
        if "subAttackPatterns" in node and len(node["subAttackPatterns"]["edges"]) > 0:
            for subnode in node["subAttackPatterns"]["edges"]:
                 attacks[subnode["node"]["x_mitre_id"].lower()]=subnode["node"]["x_opencti_stix_ids"][0]


    def set_observable(self,observable):
        self.observable=observable
        
    def collect_bundle_content(self,other_bundle:list):
        for item in other_bundle:
            self.bundle.append(item)
    
    def get_bundle(self):
        return self.bundle
    
    def load_sigma_rules(self):
        
        sigma_query="""
        query sigmarules{
          indicators(first: 3000,orderBy: valid_from,filters:{key:pattern_type,values:["SIGMA"]}){
            edges{node{standard_id,name}}
          }
        }
        """
        
        response=self.helper.api.query(sigma_query)
        
        sigmarules={}
        for node in response["data"]["indicators"]["edges"]:
            stix_id=node["node"]["standard_id"]
            sigma_name=node["node"]["name"] 
            sigmarules[sigma_name]=stix_id
        return sigmarules

    @staticmethod
    def _compute_score(stats: dict) -> int:
        """
        Compute the score for the observable.
        score = malicious_count / total_count * 100
        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)
        Returns
        -------
        int
            Score, in percent, rounded.
        """
        return round(
            (
                stats["malicious"]
                / (stats["harmless"] + stats["undetected"] + stats["malicious"])
            )
            * 100
        )

    def create_asn_belongs_to(self):
        if("asn" not in self.attributes.keys()):
            return;
        """Create AutonomousSystem and Relationship between the observable."""
        self.helper.log_debug(f'[VirusTotal] creating asn {self.attributes["asn"]}')
        as_stix = stix2.AutonomousSystem(
            number=self.attributes["asn"],
            name=self.attributes["as_owner"],
            rir=self.attributes["regional_internet_registry"],
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "belongs-to",
                self.observable["standard_id"],
                as_stix.id,
            ),
            relationship_type="belongs-to",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=as_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [as_stix, relationship]

    def _create_external_reference(
        self,
        url: str,
        description: str,
    ) -> ExternalReference:
        """
        Create an external reference with the given url.
        The external reference is added to the observable being enriched.
        Parameters
        ----------
        url : str
            Url for the external reference.
        description : str
            Description for the external reference.
        Returns
        -------
        ExternalReference
            Newly created external reference.
        """
        # Create/attach external reference
        external_reference = self.helper.api.external_reference.create(
            source_name=self.author["name"],
            url=url,
            description=description,
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=self.observable["id"],
            external_reference_id=external_reference["id"],
        )
        return external_reference

    def create_indicator_based_on(
        self,
        indicator_config: IndicatorConfig,
        pattern: str,
    ):
        """
        Create an Indicator if the positives hits >= threshold specified in the config.
        Objects created are added in the bundle.
        Parameters
        ----------
        indicator_config : IndicatorConfig
            Config for the indicator, with the threshold, limit, ...
        pattern : str
            Stix pattern for the indicator.
        """
        now_time = dt.datetime.utcnow()

        # Create an Indicator if positive hits >= ip_indicator_create_positives specified in config
        if (
            self.attributes["last_analysis_stats"]["malicious"]
            >= indicator_config.threshold
            > 0
        ):
            self.helper.log_debug(
                f"[VirusTotal] creating indicator with pattern {pattern}"
            )
            valid_until = now_time + dt.timedelta(
                minutes=indicator_config.valid_minutes
            )

            indicator = stix2.Indicator(
                created_by_ref=self.author,
                name=self.observable["observable_value"],
                description=(
                    "Created by VirusTotal connector as the positive count "
                    f"was >= {indicator_config.threshold}"
                ),
                confidence=self.helper.connect_confidence_level,
                pattern=pattern,
                pattern_type="stix",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                external_references=[self.external_reference]
                if self.external_reference is not None
                else None,
                custom_properties={
                    "x_opencti_main_observable_type": self.observable["entity_type"],
                    "x_opencti_detection": indicator_config.detect,
                    "x_opencti_score": self.score,
                },
            )
            
            
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on",
                    indicator.id,
                    self.observable["standard_id"],
                ),
                relationship_type="based-on",
                created_by_ref=self.author,
                source_ref=indicator.id,
                target_ref=self.observable["standard_id"],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle += [indicator, relationship]
            self.indicators+=[indicator.id]

    def get_opencti_file(self, sha256):
        """
        Determine whether or not an Artifact already exists in OpenCTI.

        sha256: a str representing the sha256 of the artifact's file contents
        returns: a bool indicidating the aforementioned
        """

        response = self.helper.api.stix_cyber_observable.read(
            filters=[{"key": "hashes_SHA256", "values": [sha256]}]
        )

        
        return response
    
    
    
    

    def link_malware_with_related_observable(self,malware_id,file_id,relation_description,a_relation_type):
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                a_relation_type,
                malware_id,
                file_id,
            ),
            relationship_type=a_relation_type,
            description=relation_description,
            created_by_ref=self.author,
            source_ref=malware_id,
            target_ref=file_id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [relationship]

    
    def create_file(self):
        """
        Create the File and link it to the observable.
        Parameters
        ----------
       
        """
        self.helper.log_debug(f"[VirusTotal] creating file")
        md5=self.attributes["md5"]
        sha1=self.attributes["sha1"]
        sha256=self.attributes["sha256"]
        size=self.attributes["size"]
        name=None
        x_opencti_additional_names=None
        if len(self.attributes["names"]) > 0:
            name=self.attributes["names"][0]
        if len(self.attributes["names"]) > 1:
            
            del self.attributes["names"][0]
            x_opencti_additional_names=self.attributes['names']
        hashes={};
        hashes['MD5']=md5;
        hashes['SHA1']=sha1;
        hashes['SHA256']=sha256;
        file_stix = stix2.File(
            name=name,
            hashes=hashes,
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_score": self.score,
            },
            )
        self.bundle += [file_stix]
        return file_stix

    def create_url(self, url: str):
        """
        Create the URL and link it to the observable.
        Parameters
        ----------
        ipv4 : str
            IPv4-Address to link.
        """
        self.helper.log_debug(f"[VirusTotal] creating url {url}")
        url_stix = stix2.URL(
            value=url,
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_score": self.score,
            },
            )
        self.bundle += [url_stix]
        return url_stix

    def create_domain(self, domain: str):
        """
        Create the Domain name and link it to the observable.
        Parameters
        ----------
        domain : str
            Domain-Name to link.
        """
        self.helper.log_debug(f"[VirusTotal] creating domain {domain}")
        domain_stix = stix2.DomainName(
            value=domain,
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_score": self.score,
            },
            )
        self.bundle += [domain_stix]
        return domain_stix
    
    
    def create_ip(self, ipv4: str):
        """
        Create the IPv4-Address and link it to the observable.
        Parameters
        ----------
        ipv4 : str
            IPv4-Address to link.
        """
        self.helper.log_debug(f"[VirusTotal] creating ipv4-address {ipv4}")
        ipv4_stix = stix2.IPv4Address(
            value=ipv4,
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_score": self.score,
            },
            )
        self.bundle += [ipv4_stix]
        return ipv4_stix


    def create_ip_resolves_to(self, ipv4: str):
        """
        Create the IPv4-Address and link it to the observable.
        Parameters
        ----------
        ipv4 : str
            IPv4-Address to link.
        """
        #self.helper.log_debug(f"[VirusTotal] creating ipv4-address {ipv4}")
        ipv4_stix = self.create_ip(ipv4)
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "resolves-to",
                self.observable["standard_id"],
                ipv4_stix.id,
            ),
            relationship_type="resolves-to",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=ipv4_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [relationship]

    def create_location_located_at(self):
        if "country" not in self.attributes.keys():
            return
        """Create a Location and link it to the observable."""
        self.helper.log_debug(
            f'[VirusTotal] creating location with country {self.attributes["country"]}'
        )
        location_stix = stix2.Location(
            id=Location.generate_id(self.attributes["country"], "Country"),
            created_by_ref=self.author,
            country=self.attributes["country"],
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at",
                self.observable["standard_id"],
                location_stix.id,
            ),
            relationship_type="located-at",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=location_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [location_stix, relationship]
    
    def create_report(self):
        report_name=" Virus Total graph at "+dt.datetime.utcfromtimestamp(int(time.time())).strftime("%Y-%m-%d")
        report_published=dt.datetime.utcfromtimestamp(
                    int(
                        time.time()
                    )
                )
        self.create_file()
        objects_refs=self.bundle
       # objects_refs.append(self.observable["standard_id"])
        report = stix2.Report(
                id=Report.generate_id(report_name, report_published),
                name=report_name,
                description=" Virus total observables graph at "+time.strftime("%Y-%m-%d"),
                published=report_published,
                created=dt.datetime.utcfromtimestamp(
                    int(
                        time.time()
                    )
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                modified=dt.datetime.utcfromtimestamp(
                    int(time.time())
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                report_types=["RECENT UPDATES"],
                created_by_ref=self.author.id,
#                object_marking_refs=event_markings,
                labels=["osint","Virus Total"],
                object_refs=objects_refs,
                allow_custom=True,
            )
        self.bundle.append(report)
    
    def create_note(self, abstract: str, content: str):
        """
        Create a single Note with the given abstract and content.
        The Note is inserted in the bundle.
        Parameters
        ----------
        abstract : str
            Abstract for the Note.
        content : str
            Content for the Note.
        """
        if self.observable is not None:
            self.helper.log_debug(f"[VirusTotal] creating note with abstract {abstract}")
        
            self.bundle.append(
                stix2.Note(
                    id=Note.generate_id(),
                    abstract=abstract,
                    content=content,
                    created_by_ref=self.author,
                    object_refs=[self.observable["standard_id"]],
                )
            )

    def create_notes(self):
        """
        Create Notes with the analysis results and categories.
        Notes are directly append in the bundle.
        """
        if self.attributes["last_analysis_stats"]["malicious"] != 0:
            self.create_note(
                "VirusTotal Positives",
                f"""```\n{
                json.dumps(
                    [v for v in self.attributes["last_analysis_results"].values()
                     if v["category"] == "malicious"], indent=2
                )}\n```""",
            )

        if "categories" in self.attributes:
            self.create_note(
                "VirusTotal Categories",
                f'```\n{json.dumps(self.attributes["categories"], indent=2)}\n```',
            )

    def create_yara(
        self, yara: dict, ruleset: dict, valid_from: Optional[float] = None
    ):
        """
        Create an indicator containing the YARA rule from VirusTotal and link it to the observable.
        Parameters
        ----------
        yara : dict
            Yara ruleset to use for the indicator.
        ruleset : dict
            Yara ruleset to use for the indicator.
        valid_from : float, optional
            Timestamp for the start of the validity.
        """
        self.helper.log_debug(f"[VirusTotal] creating indicator for yara {yara}")
        valid_from_date = (
            
            dt.datetime.utcnow()
            if valid_from is None
            else dt.utcfromtimestamp(valid_from)
        )
        ruleset_id = yara.get("id", "No ruleset id provided")
        self.helper.log_info(f"[VirusTotal] Retrieving ruleset {ruleset_id}")

        # Parse the rules to find the correct one.
        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset["data"]["attributes"]["rules"])
        rule_name = yara.get("rule_name", "No ruleset name provided")
        rule = [r for r in rules if r["rule_name"] == rule_name]
        if len(rule) == 0:
            self.helper.log_warning(f"No YARA rule for rule name {rule_name}")
            return

        indicator = stix2.Indicator(
            created_by_ref=self.author,
            name=yara.get("rule_name", "No rulename provided"),
            description=f"""```\n{json.dumps(
                {
                    "description": yara.get("description", "No description provided"),
                    "author": yara.get("author", "No author provided"),
                    "source": yara.get("source", "No source provided"),
                    "ruleset_id": ruleset_id,
                    "ruleset_name": yara.get(
                        "ruleset_name", "No ruleset name provided"
                    ),
                }, indent=2
            )}\n```""",
            confidence=self.helper.connect_confidence_level,
            pattern=plyara.utils.rebuild_yara_rule(rule[0]),
            pattern_type="yara",
            valid_from=self.helper.api.stix2.format_date(valid_from_date),
            custom_properties={
                "x_opencti_main_observable_type": "StixFile",
                "x_opencti_score": self.score,
            },
        )
        self.helper.log_debug(f"[VirusTotal] yara indicator created: {indicator}")
        self.indicators.append(indicator.id)
        # Create the relationships (`related-to`) between the yaras and the file.
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to",
                self.observable["standard_id"],
                indicator.id,
            ),
            created_by_ref=self.author,
            relationship_type="related-to",
            source_ref=self.observable["standard_id"],
            target_ref=indicator.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [indicator, relationship]

    @staticmethod
    def _extract_link(link: str) -> Optional[str]:
        """
        Extract the links for the external reference.
        For the gui link, observable type need to be singular.
        Parameters
        ----------
        link : str
            Original link used for the query
        Returns
        -------
            str, optional
                Link to the gui of the observable on VirusTotal website, if any.
        """
        for k, v in {
            "files": "file",
            "ip_addresses": "ip-address",
            "domains": "domain",
            "urls": "url",
        }.items():
            if k in link:
                return link.replace("api/v3", "gui").replace(k, v)
        return None

    def send_bundle(self) -> str:
        """
        Serialize and send the bundle to be inserted.
        Returns
        -------
        str
            String with the number of bundle sent.
        """
        if self.bundle is not None:
            self.helper.log_info(f"[VirusTotal] sending bundle: {self.bundle}")
            serialized_bundle = stix2.Bundle(
                objects=self.bundle, allow_custom=True
            ).serialize()
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def update_hashes(self):
        """Update the hashes (md5 and sha1) of the file."""
        for algo in ("MD5", "SHA-1", "SHA-256"):
            self.helper.log_debug(
                f'[VirusTotal] updating hash {algo}: {self.attributes[algo.lower().replace("-", "")]}'
            )
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
                input={
                    "key": f"hashes.{algo}",
                    "value": self.attributes[algo.lower().replace("-", "")],
                },
            )

    def update_labels(self):
        """Update the labels of the file using the tags."""
        self.helper.log_debug(
            f'[VirusTotal] updating labels with {self.attributes["tags"]}'
        )
        for tag in self.attributes["tags"]:
            tag_vt = self.helper.api.label.create(value=tag, color="#0059f7")
            self.helper.api.stix_cyber_observable.add_label(
                id=self.observable["id"], label_id=tag_vt["id"]
            )

    def update_names(self, main: bool = False):
        """
        Update main and additional names.
        Parameters
        ----------
        main : bool
            If True, update the main name.
        """
        self.helper.log_debug(
            f'[VirusTotal] updating names with {self.attributes["names"]}'
        )
        names = self.attributes["names"]
        if len(names) > 0 and main:
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
                input={"key": "name", "value": names[0]},
            )
            del names[0]
        if len(names) > 0:
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
                input={
                    "key": "x_opencti_additional_names",
                    "value": [n for n in names if n != self.observable["name"]],
                },
            )

    def update_size(self):
        """Update the size of the file."""
        self.helper.log_debug(
            f'[VirusTotal] updating size with {self.attributes["size"]}'
        )
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "size", "value": str(self.attributes["size"])},
        )
        
    def create_malware(self):

        malware_name=self.attributes["popular_threat_classification"]["suggested_threat_label"]
        
        malware_aliases=[malware_name.lower()]
        
        for name in self.attributes["popular_threat_classification"]["popular_threat_name"]:
            malware_aliases+=[name["value"].lower()]
        
        self.helper.log_info(f"[VirusTotal] creating malware {malware_name}")

        malware =Malware(is_family=False,
                         name=malware_name,
                         labels=["osint","Virus Total"])
        self.bundle+=[malware]
        
        family_ref=None
        for alias in malware_aliases:
            if alias in self.malwares.keys():
                family_ref = self.malwares[alias]
                break;
        
        if family_ref is not None:
            relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "variant-of",
                malware.id,
                family_ref,
            ),
            created_by_ref=self.author,
            relationship_type="variant-of",
            source_ref=malware.id,
            target_ref=family_ref,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
            )
            self.bundle+=[relationship]
        
        for indicator_id in self.indicators:
            relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "indicates",
                indicator_id,
                malware.id,
            ),
            created_by_ref=self.author,
            relationship_type="indicates",
            source_ref=indicator_id,
            target_ref=malware.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
            )
            self.bundle+=[relationship]
            
            
        self.create_notes()
        return malware.id            
     
    def get_relations(self):
        return self.relations
                
              #  for ip in contacted_ips:
     #     self.process_contacted_ip(ip,malware-id)

                      
    def match_sigma_rules(self):
       
        if "sigma_analysis_results" in self.attributes:
            sigma_analysis_results = self.attributes["sigma_analysis_results"]
            for sigma_analysis in sigma_analysis_results:
                rule_title = sigma_analysis["rule_title"]
                if rule_title in self.sigma_rules.keys():
                    rule_standard_id=self.sigma_rules[rule_title]
                    #generate the relations between the rule (indicator) and the observable and malware
                    self.indicators+=[rule_standard_id]

