import os
import yaml
import json

import csv
import time
import urllib.request
import certifi
import ssl
import zipfile
import yaml
from yaml.loader import SafeLoader
from tomlkit import dumps
import toml

from datetime import datetime
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    SimpleObservable,
    OpenCTIStix2Utils,
)

from stix2 import (
    Bundle,
    Identity,
    IntrusionSet,
    Malware,
    Tool,
    AttackPattern,
    Report,
    Indicator,
    Relationship,
    ExternalReference,
    Sighting,
    CustomObservable,
    Location,
    TLP_WHITE,
    TLP_GREEN,
    TLP_AMBER,
    TLP_RED,
    ObjectPath,
    EqualityComparisonExpression,
    ObservationExpression,
    Note,
)
from stix2.v21.observables import File, URL, NetworkTraffic
from stix2.v21.sdo import Indicator
from stix2.v21.sro import Relationship
from typing import Optional
from stix2.patterns import AndBooleanExpression
from stix2 import IPv4Address
from stix2.properties import IntegerProperty, StringProperty, TimestampProperty,ListProperty
from stix2.utils import NOW
from stix.common import references

@CustomObservable('x-opencti-text', [
    ('value', StringProperty(required=True)),
    ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ('description', StringProperty()),
    ('labels', ListProperty(StringProperty)),
    ('external_references', ListProperty(ExternalReference))])
class Text():
    pass
PATTERNTYPES = ["yara", "sigma", "pcre", "snort", "suricata"]
OPENCTISTIX2 = {
    "autonomous-system": {
        "type": "autonomous-system",
        "path": ["number"],
        "transform": {"operation": "remove_string", "value": "AS"},
    },
    "network-traffic": {"type": "network-traffic", "path": ["value"]},
    "mac-addr": {"type": "mac-addr", "path": ["value"]},
    "hostname": {"type": "x-opencti-hostname", "path": ["value"]},
    "domain": {"type": "domain-name", "path": ["value"]},
    "ipv4-addr": {"type": "ipv4-addr", "path": ["value"]},
    "ipv6-addr": {"type": "ipv6-addr", "path": ["value"]},
    "url": {"type": "url", "path": ["value"]},
    "email-address": {"type": "email-addr", "path": ["value"]},
    "email-subject": {"type": "email-message", "path": ["subject"]},
    "mutex": {"type": "mutex", "path": ["name"]},
    "file-name": {"type": "file", "path": ["name"]},
    "file-path": {"type": "file", "path": ["name"]},
    "file-md5": {"type": "file", "path": ["hashes", "MD5"]},
    "file-sha1": {"type": "file", "path": ["hashes", "SHA-1"]},
    "file-sha256": {"type": "file", "path": ["hashes", "SHA-256"]},
    "directory": {"type": "directory", "path": ["path"]},
    "registry-key": {"type": "windows-registry-key", "path": ["key"]},
    "registry-key-value": {"type": "windows-registry-value-type", "path": ["data"]},
    "pdb-path": {"type": "file", "path": ["name"]},
    "x509-certificate-issuer": {"type": "x509-certificate", "path": ["issuer"]},
    "x509-certificate-serial-number": {
        "type": "x509-certificate",
        "path": ["serial_number"],
    },
    "text": {"type": "x-opencti-text", "path": ["value"]},
}
FILETYPES = ["file-name", "file-md5", "file-sha1", "file-sha256"]


class Sigma:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.sigma_rules_url=get_config_variable("SIGMA_RULES_URL", ["sigma", "github_url"], config)
        self.elastic_rules_url=get_config_variable("ELASTIC_RULES_URL", ["elastic", "github_url"], config)
        self.sample_size=get_config_variable("SAMPLE8SIZE", ["connector", "sample_size"], config)

        self.sigma_rules_interval=get_config_variable("SIGMA_RULES_INTERVAL", ["sigma_rules", "interval"], config)
       
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.attacks_refs=self.load_attacks()
    def get_interval(self):
        return int(self.sigma_rules_interval)

    def next_run(self, seconds):
        return
    
    def load_attacks(self):
        
        attacks_query="""query attacks{
                                      attackPatterns(first:2000 orderBy: x_mitre_id){
                                        edges{
                                          node{
                                            x_mitre_id
                                            x_opencti_stix_ids
                                            subAttackPatterns{edges{node{x_mitre_id
                                                                        x_opencti_stix_ids
                                                                        }}}
                                          }
                                          
                                        }
                                      }
                                    }
        """
        
        response=self.helper.api.query(attacks_query)
        
        attacks={}
        for node in response["data"]["attackPatterns"]["edges"]:
            self.process_node(node["node"], attacks)    
        return attacks

    def process_node(self,node,attacks):
        if(len(node["x_opencti_stix_ids"]) > 0):
            mitre_id=node["x_mitre_id"].lower()
            attacks[mitre_id]=node["x_opencti_stix_ids"][0]
        if "subAttackPatterns" in node and len(node["subAttackPatterns"]["edges"]) > 0:
            for subnode in node["subAttackPatterns"]["edges"]:
                 attacks[subnode["node"]["x_mitre_id"].lower()]=subnode["node"]["x_opencti_stix_ids"][0]
            
    def run(self):
        while True:

            self.helper.log_info("Fetching Sigma-rules  dataset...")
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                
                last_run_key="last_run"
               
                current_state = self.helper.get_state()
                if current_state is not None and last_run_key in current_state:
                    last_run = current_state[last_run_key]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                    )
                    
                else:
                    last_run = None
                    self.helper.log_info(" Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) >= (int(self.sigma_rules_interval) * 60 * 60 * 24)
                ):
                    self.helper.log_info(" Connector will run!")
                    
                    full_data=(last_run is None)
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "SIGMA-RULES run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    
                    self.process_rules(work_id,now,self.sigma_rules_url,"Sigma")
                    
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.api.work.to_processed(work_id, message)
                    
                    friendly_name = "ELASTIC-RULES run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    self.process_rules(work_id,now,self.elastic_rules_url,"Elastic")
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.api.work.to_processed(work_id, message)
                        # Store the current timestamp as a last run
                   
                    self.helper.set_state({last_run_key: timestamp})
                    
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval(), 2))
                        + " days"
                    )
                else:
                    new_interval = (self.get_interval()*60*60*24) - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
            time.sleep(60)
    def process_rules(self,work_id,time,url,source):
        
        self.download_rules(url,source)
        self.extract_rule(work_id,source, time)
        return None
    
    
       
    def download_rules(self,url,source):
        
        if url is None:
            self.helper.log_warning("You must provide a sigma rules zip file url")
        else:
            response = urllib.request.urlopen(
                        url, context=ssl.create_default_context(cafile=certifi.where())
                    )
            image = response.read()
            with open(
                os.path.dirname(os.path.abspath(__file__)) + "/data.zip", "wb"
            ) as file:
                file.write(image)
    #self.helper.log_info("Unzipping the file")
            with zipfile.ZipFile(os.path.dirname(os.path.abspath(__file__)) + "/data.zip", 'r') as zip_ref:
                zip_ref.extractall(os.path.dirname(os.path.abspath(__file__)))

        return None
    
    def extract_rule(self,work_id,source,date):  
        with zipfile.ZipFile(os.path.dirname(os.path.abspath(__file__)) + "/data.zip", 'r') as zip_ref:
            zip_ref.extractall(os.path.dirname(os.path.abspath(__file__)))
        walk_dir=os.path.dirname(os.path.abspath(__file__))+ "/detection-rules-main/rules/"
        if(source == 'Sigma'):
            walk_dir=os.path.dirname(os.path.abspath(__file__))+ "/sigma-master/rules/"
        
        bundle_objects = []
        object_refs=[]
        
        running=True
        treated_rules=0
        for root, subdirs, files in os.walk(walk_dir):
            if not running:
                break
            for filename in files:
                if source=='Elastic' and filename.endswith('.toml'):
                    self.process_elastic_rule(os.path.join(root, filename),filename, date,bundle_objects,object_refs)
                elif source=='Sigma' and filename.endswith('.yml'):
                    self.process_sigma_rule(os.path.join(root, filename), date,bundle_objects,object_refs)
                treated_rules+=1
                if self.sample_size is not None and treated_rules >= self.sample_size:
                    running=False
                    break
        author = Identity(
                name=source,
                identity_class="organization",
            )
        object_refs.append(author)
        event_markings = [TLP_WHITE]
        report = Report(
                    id=OpenCTIStix2Utils.generate_random_stix_id(
                        "report"
                        ),
                    name=source+" detection rules for "+time.strftime("%Y-%m-%d"),
                    description=source+" detection rules for "+time.strftime("%Y-%m-%d"),
                    published=datetime.utcfromtimestamp(
                        int(
                            time.time()
                        )
                    ),
                    created=datetime.utcfromtimestamp(
                        int(
                            time.time()
                        )
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    modified=datetime.utcfromtimestamp(
                        int(time.time())
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    report_types=["RECENT UPDATES"],
                    created_by_ref=author,
                    object_marking_refs=event_markings,
                    labels=["osint","rules",source],
                    object_refs=object_refs,
                    custom_properties={
                        "x_opencti_report_status": 2,
                        "x_opencti_files": [],
                    },
                    allow_custom=True,
                )
            
            
        bundle_objects.append(report)
        
        try:
            bundle = Bundle(
                objects=bundle_objects, allow_custom=True
            ).serialize()
            self.helper.send_stix2_bundle(
                bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
#            if os.path.exists(
#                os.path.dirname(os.path.abspath(__file__)) + "/data.csv"
#            ) and self.bazaar_data_path is None:
#                os.remove(
#                    os.path.dirname(os.path.abspath(__file__)) + "/data.csv"
#                )
                
        except Exception as e:
            self.helper.log_error(str(e))
             
        message = "Connector successfully processed BAZAAR "
        self.helper.api.work.to_processed(work_id, message)

        return None

    def process_elastic_rule(self,file_path,filename,time,bundle_objects,object_refs):
        self.helper.log_info("Processing elastic detection rules...")
        with open(file_path) as f:
            try:
                data=toml.load(f)
                references=[]
                if "references" in data["rule"]:
                    ext_refs=data["rule"]["references"]
                    for ref in ext_refs:
                        references.append(ExternalReference(
                                        source_name="Elastic Rules",
                                        url=ref,
                                    ) )
                path_index = file_path.index('/rules')+7
                rule_url='https://github.com/elastic/detection-rules/blob/main/rules/'+file_path[path_index:]
                rule_ref = ExternalReference(
                                        source_name="Elastic Rules",
                                        url=rule_url,
                                        external_id=data["rule"]["rule_id"]
                                    )
                
                persisted_rule_ref=self.helper.api.external_reference.create(**rule_ref)
                
                references.append(rule_ref)
                
                file_data=self.helper.api.external_reference.add_file(
                            id=persisted_rule_ref["id"],
                            file_name=filename,
                            data=toml.dumps(data),
                            mime_type="text/plain",
                       )
                tags=data["rule"]["tags"]
                tags.append("elastic-rule")
                indicator = Indicator(type="indicator",
                                      id="indicator--"+data["rule"]["rule_id"],
                                      name=data["rule"]["name"],
                                      description=data["rule"]["description"],
                                      created=datetime.strptime(data["metadata"]["creation_date"], '%Y/%m/%d'),
                                      modified=datetime.strptime(data["metadata"]["updated_date"], '%Y/%m/%d'),
                                      pattern="[elasticsearch:value = '"+data["rule"]["query"]+"']",
                                      pattern_type="STIX",
                                      labels=tags,
                                      external_references=references)
                
                               
                object_refs.append(indicator)
                bundle_objects.append(indicator)
                
                mitre_ids=[]
                tecnics=data["rule"]["threat"]
                for threat in tecnics:
                    for item in threat["technique"]:
                        mitre_ids.append(item["id"].lower())
                        if "subtechnique" in item:
                            for subtech in item["subtechnique"]:
                                mitre_ids.append(subtech["id"].lower())
                    
                
                attack_relations=[]
                self.link_with_attack(indicator.id,mitre_ids,attack_relations)
                if len(attack_relations)  > 0:
                    for relation in attack_relations:
                        bundle_objects.append(relation)
                        object_refs.append(relation)

            except Exception as e:
                self.helper.log_error(file_path)
                self.helper.log_error(str(e))
        return None
    
    def link_with_attack(self,stix_indicator_id,mitre_ids,relations_collector):
        attacks_relations = []
        for mitre_id in mitre_ids:
            if mitre_id in self.attacks_refs.keys():
                relation =  Relationship(relationship_type='indicates',
                                                source_ref=stix_indicator_id,
                                                target_ref=self.attacks_refs[mitre_id])
                relations_collector.append(relation)
        
        return None
    
    def process_sigma_rule(self,file_path,time,bundle_objects,object_refs):
                #print('\t- file %s (full path: %s)' % (filename, file_path))
        with open(file_path) as f:
            try:
                data = yaml.load(f, Loader=SafeLoader)
                detection = data["title"]
                references=[]
                if "references" in data:
                    ext_refs=data["references"]
                    for ref in ext_refs:
                        references.append(ExternalReference(
                                        source_name="Elastic Rules",
                                        url=ref) )
                cti_id="indicator--"+data["id"]
                
                tags=data["tags"]
                mitre_ids=[]
                for tag in tags:
                    sptags=tag.split('.')
                    if len(sptags)>1 and sptags[1].startswith('t'):
                        mitre_ids.append(sptags[1])
                
                attack_relations=[]
                self.link_with_attack(cti_id,mitre_ids,attack_relations)
                if len(attack_relations)  > 0:
                    for relation in attack_relations:
                        bundle_objects.append(relation)
                        object_refs.append(relation)

                tags.append("sigma-rule")
                tags.append(data["status"])
                modifiedtime=time
                if "modified" in data:
                    modifiedtime=datetime.strptime(data["modified"], '%Y/%m/%d')
                    
                sigma_rule = Indicator(id=cti_id,
                                       type="indicator",
                                        name=data["title"],
                                        pattern=yaml.dump(data),
                                        pattern_type="sigma",
                                        labels=tags,
                                        created=datetime.strptime(data["date"], '%Y/%m/%d'),
                                        modified=modifiedtime,
                                        external_references=references)
                object_refs.append(sigma_rule)
    
                bundle_objects.append(sigma_rule)
    
                
                #print(yaml.dump(data))
            except Exception as e:
                self.helper.log_error(str(e))
        return None
        
         
    def load_malwares(self):
        
        malware_query="""query Malwares($malwares_number:Int){

                        malwares(first: $malwares_number){
                          edges{
                            node{
                              x_opencti_stix_ids
                              name
                            }
                          }
              }
            }
        """
        args={"malwares_number": 500}
        response=self.helper.api.query(malware_query,args)
        
        malwares={}
        for malware in response["data"]["malwares"]["edges"]:
            if(len(malware["node"]["x_opencti_stix_ids"]) > 0):
                malwares[malware["node"]["name"].lower()]=malware["node"]["x_opencti_stix_ids"][0]
        
        return malwares
            


if __name__ == "__main__":
    try:
        sigma_rules_connector=Sigma()
        sigma_rules_connector.run()
     
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
