import os
import yaml
import json

import csv
import time
import urllib.request
import certifi
import ssl

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
    ObservedData,
    Relationship,
    ExternalReference,
    Sighting,
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
from stix2.v21.observables import File, URL, NetworkTraffic, DomainName,\
    WindowsRegistryKey, Mutex, Process
from stix2.v21.sdo import Indicator, MalwareAnalysis
from stix2.v21.sro import Relationship
from typing import Optional
from stix2.patterns import AndBooleanExpression
from stix2 import IPv4Address
from symbol import try_stmt
from stix2.v20.vocab import HASHING_ALGORITHM

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


class VirusTotalGraphGenerator:
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
        self.sample_size=get_config_variable("SAMPLE_SIZE", ["abuse_ch", "sample_size"], config)

        self.misp_url=get_config_variable("MISP_URL", ["misp", "url"], config)
        self.misp_reference_url = get_config_variable(
            "MISP_REFERENCE_URL", ["misp", "reference_url"], config
        )
        self.misp_key = get_config_variable("MISP_KEY", ["misp", "key"], config)
        self.misp_ssl_verify = get_config_variable(
            "MISP_SSL_VERIFY", ["misp", "ssl_verify"], config
        )
        self.misp_datetime_attribute = get_config_variable(
            "MISP_DATETIME_ATTRIBUTE",
            ["misp", "datetime_attribute"],
            config,
            False,
            "timestamp",
        )
        self.misp_create_report = get_config_variable(
            "MISP_CREATE_REPORTS", ["misp", "create_reports"], config
        )
        self.misp_create_indicators = get_config_variable(
            "MISP_CREATE_INDICATORS", ["misp", "create_indicators"], config
        )
        self.misp_create_observables = get_config_variable(
            "MISP_CREATE_OBSERVABLES", ["misp", "create_observables"], config
        )
        self.misp_create_object_observables = get_config_variable(
            "MISP_CREATE_OBJECT_OBSERVABLES",
            ["misp", "create_object_observables"],
            config,
        )
        self.misp_report_type = (
            get_config_variable("MISP_REPORT_TYPE", ["misp", "report_type"], config)
            or "MISP Event"
        )
        self.misp_import_from_date = get_config_variable(
            "MISP_IMPORT_FROM_DATE", ["misp", "import_from_date"], config
        )
        self.misp_import_tags = get_config_variable(
            "MISP_IMPORT_TAGS", ["misp", "import_tags"], config
        )
        self.misp_import_tags_not = get_config_variable(
            "MISP_IMPORT_TAGS_NOT", ["misp", "import_tags_not"], config
        )
        self.import_creator_orgs = get_config_variable(
            "MISP_IMPORT_CREATOR_ORGS", ["misp", "import_creator_orgs"], config
        )
        self.import_owner_orgs = get_config_variable(
            "MISP_IMPORT_OWNER_ORGS", ["misp", "import_owner_orgs"], config
        )
        self.import_distribution_levels = get_config_variable(
            "MISP_IMPORT_DISTRIBUTION_LEVELS",
            ["misp", "import_distribution_levels"],
            config,
        )
        self.import_threat_levels = get_config_variable(
            "MISP_IMPORT_THREAT_LEVELS", ["misp", "import_threat_levels"], config
        )
        self.import_only_published = get_config_variable(
            "MISP_IMPORT_ONLY_PUBLISHED", ["misp", "import_only_published"], config
        )
        self.import_with_attachments = bool(
            get_config_variable(
                "MISP_IMPORT_WITH_ATTACHMENTS",
                ["misp", "import_with_attachments"],
                config,
                isNumber=False,
                default=False,
            )
        )
        self.import_to_ids_no_score = get_config_variable(
            "MISP_IMPORT_TO_IDS_NO_SCORE",
            ["misp", "import_to_ids_no_score"],
            config,
            True,
        )
        self.import_unsupported_observables_as_text = bool(
            get_config_variable(
                "MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT",
                ["misp", "import_unsupported_observables_as_text"],
                config,
                isNumber=False,
                default=False,
            )
        )

        self.bazaar_full_url = get_config_variable(
            "BAZAAR_FULL_URL", ["bazaar", "full_csv_url"], config
        )
        
        self.bazaar_daily_url = get_config_variable(
            "BAZAAR_DAILY_URL", ["bazaar", "daily_url"], config
        )
        
        self.bazaar_data_path = get_config_variable(
            "BAZAAR_DATA_PATH", ["bazaar", "data_path"], config
        )

        self.urlhaus_full_url = get_config_variable(
            "URLHAUS_FULL_URL", ["urlhaus", "full_csv_url"], config
        )
        
        self.urlhaus_daily_url = get_config_variable(
            "URLHAUS_DAILY_URL", ["urlhaus", "daily_url"], config
        )
        
        self.urlhaus_data_path = get_config_variable(
            "URLHAUS_DATA_PATH", ["urlhaus", "data_path"], config
        )
        
        self.threatfox_full_url = get_config_variable(
            "THREATFOX_FULL_URL", ["threatfox", "full_csv_url"], config
        )
        
        self.threatfox_daily_url = get_config_variable(
            "THREATFOX_DAILY_URL", ["threatfox", "daily_url"], config
        )
        
        self.threatfox_data_path = get_config_variable(
            "THREATFOX_DATA_PATH", ["threatfox", "data_path"], config
        )

        self.abuse_ch_import_offline = get_config_variable(
            "ABUSECH_IMPORT_OFFLINE", ["abuse_ch", "import_offline"], config, False, True
        )
        
        self.abuse_ch_interval = get_config_variable(
            "ABUSECH_INTERVAL", ["abuse_ch", "interval"], config, True
        )
        
        self.create_indicators = get_config_variable(
            "ABUSECH_CREATE_INDICATORS",
            ["abuse_ch", "create_indicators"],
            config,
            False,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Abuse.ch",
            description="abuse.ch is operated by a random swiss guy fighting malware for non-profit, running a couple of projects helping internet service providers and network operators protecting their infrastructure from malware.",
        )
        
        self.malwares=self.load_malwares()
        self.attacks_refs=self.load_attacks()
        
        self.past_days = get_config_variable(
            "PAST_DAYS",
            ["abuse_ch", "past_days"],
            config,
            True,
            None,
        )
        self.start_day = get_config_variable(
            "START_DAY",
            ["abuse_ch", "start_day"],
            config,
            False,
            None,
        )
        if self.start_day is not None:
            self.start_time=(int)(datetime.timestamp(datetime(
                                                    year=self.start_day.year,
                                                    month=self.start_day.month,
                                                    day=self.start_day.day
                                                 )))
        self.single_source = get_config_variable(
            "SINGLE_SOURCE",
            ["abuse_ch", "single_source"],
            config,
            False,
            None,
        )
        
        
    def get_interval(self):
        return int(self.abuse_ch_interval)

    def next_run(self, seconds):
        return
    def generate_test_Graph(self):
        timestamp = int(time.time())
        try:
            bundle_objects=[]
            
            vt_lines = self.load_file();
            for vt_obj in vt_lines:
                json_vt=json.loads(vt_obj);
                self.processLine(json_vt,bundle_objects)
                
            bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
            
            
        
            
        except Exception as e:
            print(str(e))
        return timestamp;
   
    def generateGraph(self):
        timestamp = int(time.time())
        try:
            bundle_objects=[]
            object_refs=[]

            author = Identity(
                name="Virus Total",
                identity_class="organization",
            )
            bundle_objects.append(author)
            event_markings = [TLP_WHITE]
            
            friendly_name = "vtgraph"+" run @ " + datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            vt_lines = self.load_file();
            for vt_obj in vt_lines:
                json_vt=json.loads(vt_obj);
                self.processLine(json_vt,event_markings,author,bundle_objects)
            
            report_name=" Virus Total graph at "+time.strftime("%Y-%m-%d")
            report_published=atetime.utcfromtimestamp(
                        int(
                            time.time()
                        )
                    )
            report = Report(
                    id=Report.generate_id(report_name, report_published),
                    name=report_name,
                    description=" Virus total observables graph at "+time.strftime("%Y-%m-%d"),
                    published=report_published,
                    created=datetime.utcfromtimestamp(
                        int(
                            time.time()
                        )
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    modified=datetime.utcfromtimestamp(
                        int(time.time())
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    report_types=["RECENT UPDATES"],
                    created_by_ref=author.id,
                    object_marking_refs=event_markings,
                    labels=["osint","Virus Total"],
                    object_refs=bundle_objects,
                    allow_custom=True,
                )
            
            bundle_objects.append(report)
            
              
            bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
            self.helper.log_info("Sending event STIX2 bundle")
            self.helper.send_stix2_bundle(
                bundle, work_id=work_id, update=self.update_existing_data
                )
            message = " Connector successfully run" ;
            self.helper.log_info(message)
            self.helper.api.work.to_processed(work_id, message)
        except Exception as e:
            self.helper.log_error(str(e))
        return timestamp;
       
    def processLine(self,data,event_markings,author,bundle_objects):
        
        abuseData=data['abuse_data'];
        obs_type=data['type']
        
        if(obs_type=="file"):
            self.processFile(data,event_markings,author,bundle_objects)
        
                
        
     
    def processFile(self,data,event_markings,author,bundle_objects):
        
        md5=data["md5"]
        sha1=data["sha1"]
        sha256=data["sha256"]
        size=data["size"]
        name=None
        x_opencti_additional_names=None
        if len(data["names"]) > 0:
            name=data["names"][0]
        if len(data["names"]) > 1:
            
            del data["names"][0]
            x_opencti_additional_names=data['names']
        hashes={};
        hashes['MD5']=md5;
        hashes['SHA1']=sha1;
        hashes['SHA256']=sha256;

        file =  File(allow_custom=True,
                     name=name,
                     hashes=hashes,
                     additional_names=x_opencti_additional_names,
                     size=size)
        
        bundle_objects.append(file)
        self.createFileIndicator(file,data,event_markings,author,bundle_objects)
        
    def createFileIndicator(self,file,data,event_markings,author,bundle_objects):
        pattern_type="stix"
        pattern="[file:hashes.md5 = '"+data["md5"]+"']"# and file.hashes.sha1 = '"+sha1+"' and file.hashes.sha256 = '"+sha256+"']"
       #valid_from=data['abuse_data']["first_seen_utc"]
        valid_from=int(time.time());
        #confidence=self.get_file_indicator_confidence(data)
        indicator = Indicator(
                              pattern_type=pattern_type,
                              pattern=pattern,
                              labels=["osint","Virus Total"])
        bundle_objects.append(indicator)
        
        malware=self.getMalware(data,event_markings,author,bundle_objects)
        self.createRelation('indicates',indicator.id,malware.id,bundle_objects)
        
        observedData = ObservedData(number_observed=1,
                                    first_observed=indicator.valid_from,
                                    last_observed=indicator.valid_from,
                                    object_refs=[file.id],
                                    labels=["osint","Virus Total"])
        
        bundle_objects.append(observedData)
        
        self.createRelation('based-on',indicator.id,observedData.id,bundle_objects)
        
        self.process_vt_relations(data,event_markings,author,malware,file,indicator,bundle_objects)

    def getMalware(self,data,event_markings,author,bundle_objects):
    
        malware_name=data["popular_threat_classification"]["suggested_threat_label"]
        
        malware =Malware(is_family=False,
                         name=malware_name,
                         labels=["osint","Virus Total"])
        
        bundle_objects.append(malware)
        return malware;
    
    def process_vt_relations(self,data,event_markings,author,malware,file,indicator,bundle_objects):
        vt_relations=data["relations"]

        if("contacted_ips" in vt_relations):
            contacted_ips=vt_relations["contacted_ips"]
            for ip in contacted_ips:
                self.process_contacted_ip(ip,data,malware,file,indicator,bundle_objects)

        if("contacted_domains" in vt_relations):
            contacted_domains=vt_relations["contacted_domains"]
            for domain in contacted_domains:
                self.process_contacted_domain(domain,data,malware,file,indicator,bundle_objects)
                
        if("contacted_urls" in vt_relations):
            contacted_urls=vt_relations["contacted_urls"]
            for url in contacted_urls:
                self.process_contacted_url(url,data,malware,file,indicator,bundle_objects)
                
        if("dropped_files" in vt_relations):                
            dropped_files=vt_relations["dropped_files"]
            for dropped_file in dropped_files:
                self.process_dropped_file(dropped_file,malware,file,indicator,bundle_objects)

        if("execution_parents" in vt_relations):                        
            execution_parents=vt_relations["execution_parents"]
            for execution_parent in execution_parents:
                self.process_related_file(execution_parent,malware,file,indicator,bundle_objects)
                
        if("compressed_parents" in vt_relations):                                        
            compressed_parents=vt_relations["compressed_parents"]
            for compressed_parent in compressed_parents:
                self.process_related_file(compressed_parent,malware,file,indicator,bundle_objects)

        if("behaviours" in data):                                                    
            behaviours=data["behaviours"]
            self.process_behaviours(behaviours,malware,file,indicator,bundle_objects)

            
        if("last_analysis_results" in data):                                                                
                   malware_analysis=data["last_analysis_results"]
                   for analysis_name in malware_analysis:
                       analysis=malware_analysis[analysis_name]
                       self.process_malware_analysis(analysis_name,analysis, malware, file, indicator, bundle_objects)
        if("sigma_analysis_results" in data):                                                                        
            sigma_analysis_list=data["sigma_analysis_results"]
            for sigma_analysis in sigma_analysis_list:
                self.process_sigma_analysis(sigma_analysis, malware, file, indicator, bundle_objects)


        print('ok')
        
    def process_behaviours(self,behaviours,malware,file,indicator,bundle_objects):
        if("mutexes_created" in behaviours):                                                    
            mutexes_created=behaviours["mutexes_created"]
            for mutex in mutexes_created:
                self.process_mutex(mutex,malware,file,indicator,bundle_objects)
        if("registry_keys_deleted" in behaviours):                                                            
            registry_keys_deleted=behaviours["registry_keys_deleted"]
            for key in registry_keys_deleted:
                self.process_reg_key(key,malware,file,indicator,bundle_objects)
        if("processes_injected" in behaviours):                                                                   
            processes_created=behaviours["processes_injected"]
            for process in processes_created:
                self.process_process(process,malware,file,indicator,bundle_objects)
        if("attack_techniques" in behaviours):                                                                   
            attack_techniques=behaviours["attack_techniques"]
            for attack_technique in attack_techniques:
                self.process_attack_technique(attack_technique,malware,file,indicator,bundle_objects)

   
    def process_contacted_ip(self,ip,data,malware,file,indicator,bundle_objects):
        ipAddress = IPv4Address(value=ip)
        bundle_objects.append(ipAddress)
        self.createRelation("communicates-with",malware.id,ipAddress.id,bundle_objects)

    def process_contacted_domain(self,domain,data,malware,file,indicator,bundle_objects):
        domain = DomainName(value=domain)
        bundle_objects.append(domain)
        self.createRelation("communicates-with",malware.id,domain.id,bundle_objects)
    
    def process_contacted_url(self,url,data,malware,file,indicator,bundle_objects):
        url = URL(value=url)
        bundle_objects.append(url)
        self.createRelation("communicates-with",malware.id,url.id,bundle_objects)

    def process_mutex(self,mutex,malware,file,indicator,bundle_objects):
        mutex = Mutex(name=mutex)
        bundle_objects.append(mutex)
        self.createRelation("related-to",malware.id,mutex.id,bundle_objects)

    def process_process(self,process,malware,file,indicator,bundle_objects):
        process = Process(cwd=process)
       # bundle_objects.append(process)
        #self.createRelation("related-to",malware.id,process.id,bundle_objects)

    def process_attack_technique(self,technique,malware,file,indicator,bundle_objects):
        if technique.lower() in self.attacks_refs:
            self.createRelation("uses", malware.id, self.attacks_refs[technique.lower()], bundle_objects)
            self.createRelation("indicates", indicator.id, self.attacks_refs[technique.lower()], bundle_objects)
        
       # bundle_objects.append(process)
        #self.createRelation("related-to",malware.id,process.id,bundle_objects)

    def process_reg_key(self,key,malware,file,indicator,bundle_objects):
        key = WindowsRegistryKey(key=key)
        bundle_objects.append(key)
        self.createRelation("related-to",malware.id,key.id,bundle_objects)

    def process_dropped_file(self,data,malware,file,indicator,bundle_objects):
        md5=data["md5"]
        sha1=data["sha1"]
        sha256=data["sha256"]
        size=data["size"]
        name=None
        x_opencti_additional_names=None
        if len(data["names"]) > 0:
            name=data["names"][0]
        if len(data["names"]) > 1:
            
            del data["names"][0]
            x_opencti_additional_names=data['names']
        hashes={};
        hashes['MD5']=md5;
        hashes['SHA1']=sha1;
        hashes['SHA256']=sha256;

        file =  File(allow_custom=True,name=name,hashes=hashes,additional_names=x_opencti_additional_names,size=size)
        bundle_objects.append(file)
     
        self.createRelation("drops",malware.id,file.id,bundle_objects)

    def process_related_file(self,data,malware,file,indicator,bundle_objects):
        md5=data["md5"]
        sha1=data["sha1"]
        sha256=data["sha256"]
        size=data["size"]
        name=None
        x_opencti_additional_names=None
        if len(data["names"]) > 0:
            name=data["names"][0]
        if len(data["names"]) > 1:
            
            del data["names"][0]
            x_opencti_additional_names=data['names']
        hashes={};
        hashes['MD5']=md5;
        hashes['SHA1']=sha1;
        hashes['SHA256']=sha256;

        related_file =  File(allow_custom=True,name=name,hashes=hashes,additional_names=x_opencti_additional_names,size=size)
        bundle_objects.append(file)
     
        self.createRelation("related-to",malware.id,related_file.id,bundle_objects)
        self.createRelation("related-to",file.id,related_file.id,bundle_objects)

    def process_malware_analysis(self,analysis_name,analysis,malware,file,indicator,bundle_objects):
        
        engine_version=analysis['engine_version']
        engine_name=analysis['engine_name']
        method=analysis['method']
        category=analysis['category']

        malware_analysis = MalwareAnalysis(result=category,analysis_engine_version=engine_version,product=engine_name)
        bundle_objects.append(malware_analysis)
        self.createRelation("related-to",malware_analysis.id,malware.id,bundle_objects)

    def process_sigma_analysis(self,sigma_analysis,malware,file,indicator,bundle_objects):
        
        rule_id=sigma_analysis['rule_id']
        rule_author=sigma_analysis['rule_author']
        rule_description=sigma_analysis['rule_description']
        rule_title=sigma_analysis['rule_title']
        rule_level=sigma_analysis['rule_level']
        
        pattern="file.hashes.sha1 = '1234'"
        
        #sigma_analysis = Indicator(indicator_types="malicious-activity",name=rule_title,description=rule_description,pattern_type="sigma",pattern=pattern)
        #bundle_objects.append(sigma_analysis)
        #self.createRelation("indicates",sigma_analysis.id,malware.id,bundle_objects)
            
#    def get_file_indicator_confidence(self,data):
#        lastAnalysisResults=data["last_analysis_stats"]
#        positives=0;
#        total=0;
#        for key, value in lastAnalysisResults.items():
#            if
    
    def createRelation(self,relationName,sourceId,targetId,bundle_objects):    
        relation=Relationship(relationship_type=relationName, source_ref=sourceId,target_ref=targetId)
        bundle_objects.append(relation)
        
    def load_file(self):
        vt_lines=[]
        with open("/data/osint/vt/bazaar-test.json",'r') as file:
            vt_lines=file.readlines();
        return vt_lines

    def run_test(self):
        self.generate_test_Graph()
        
    def run(self):
        while True:

            self.helper.log_info("Fetching VirusTotal  graphs...")
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                last_date_injected=None
                last_run_key="last_run"
                last_date_injected_key="last_date_injected"
                current_state = self.helper.get_state()
                if current_state is not None and last_run_key in current_state:
                    last_run = current_state[last_run_key]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                    )
                    if(last_date_injected_key in current_state):
                        last_date_injected = current_state[last_date_injected_key]
                        self.helper.log_info(
                        "Connector last download: "
                        + last_date_injected
                    )
                else:
                    last_run = None
                    self.helper.log_info(" Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) >= (int(self.abuse_ch_interval) * 60 * 60 * 24)):
                    self.helper.log_info(" Connector will run!")
                    
                    
                    now = datetime.utcfromtimestamp(timestamp)
                           
                    last_injected_timestamp= self.generateGraph();
                    
                    last_date_injected = datetime.fromtimestamp(last_injected_timestamp).strftime("%Y-%m-%d")
                        # Store the current timestamp as a last run
                   
                    self.helper.set_state({last_run_key: timestamp,last_date_injected_key:last_date_injected})
                    
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

    
    def load_malwares(self):
        
        malware_query="""query Malwares($malwares_number:Int){

                        malwares(first: $malwares_number){
                          edges{
                            node{
                              x_opencti_stix_ids
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
            if(len(malware["node"]["x_opencti_stix_ids"]) > 0):
                malwares[malware["node"]["name"].lower()]=malware["node"]["x_opencti_stix_ids"][0]
        
        return malwares
            

 



if __name__ == "__main__":
    try:
        vtConnector = VirusTotalGraphGenerator()
        vtConnector.run()
     
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
