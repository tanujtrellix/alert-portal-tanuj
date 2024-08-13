import json
import uuid
from datetime import datetime

class Product:
    def __init__(self, name, vendor_name, version):
        self.name = name
        self.vendor_name = vendor_name
        self.version = version

class Metadata:
    def __init__(self, tenant_id, customer_id, silent, product, analytical, processing_stage_time, labels):
        self.tenant_id = tenant_id
        self.customer_id = customer_id
        self.silent = silent
        self.product = product
        self.analytical = analytical
        self.processing_stage_time = processing_stage_time
        self.labels = labels

class Phase:
    def __init__(self, phase, phase_id):
        self.phase = phase
        self.phase_id = phase_id

class Event:
    def __init__(self, id, source, iocs_list):
        self.id = id
        self.source = source
        self.iocs_list = iocs_list

class AttackTechnique:
    def __init__(self, uid):
        self.uid = uid

class AttackTactic:
    def __init__(self, uid):
        self.uid = uid

class Attack:
    def __init__(self, technique, tactics, version):
        self.technique = technique
        self.tactics = tactics
        self.version = version

class Analytic:
    def __init__(self, uid, name, description, origin):
        self.uid = uid
        self.name = name
        self.description = description
        self.origin = origin

class Finding:
    def __init__(self, uid, supporting_data, related_events):
        self.uid = uid
        self.supporting_data = supporting_data
        self.related_events = related_events

class Remediation:
    def __init__(self, references):
        self.references = references

class RelatedEvent:
    def __init__(self, ds_name, uid):
        self.ds_name = ds_name
        self.uid = uid

class AlertMessage:
    def __init__(self, remediation, metadata, kill_chain, evidence, attacks, time, severity_id, message, finding, risk_level_id, analytic, confidence_id):
        self.remediation = remediation
        self.metadata = metadata
        self.kill_chain = kill_chain
        self.evidence = evidence
        self.attacks = attacks
        self.time = time
        self.severity_id = severity_id
        self.message = message
        self.finding = finding
        self.risk_level_id = risk_level_id
        self.analytic = analytic
        self.confidence_id = confidence_id
        self.intel_available = False
        self.sources = ""

    def build_source_list(self, events):
        sources = set()
        for event in events:
            sources.add(event.source)
        for event in self.evidence['source_events']['helix_events']:
            sources.add(event['source'])
        self.sources = ','.join(sources)

    def update_intel_availability(self, events):
        for event in events:
            if len(event.iocs_list) > 0:
                self.intel_available = True
                return
        for event in self.evidence['source_events']['helix_events']:
            if len(event.get('iocs_list', [])) > 0:
                self.intel_available = True
                return

    def is_field_match(self):
        if len(self.finding.related_events) == 1 and len(self.evidence['source_events']['helix_events']) == 1:
            related_event = self.finding.related_events[0]
            source_event = self.evidence['source_events']['helix_events'][0]
            if source_event['id'] == related_event.uid:
                return True
        return False

    def get_recommended_actions(self):
        if len(self.remediation.references) > 0:
            recommended_actions = {'actions': self.remediation.references}
            return json.dumps(recommended_actions)
        return None

    def validate(self):
        if len(self.finding.related_events) == 0:
            print("No related events")
            return False
        if len(self.evidence['source_events']['helix_events']) == 0:
            print("No source events")
            return False
        if self.metadata.customer_id == "" and self.metadata.tenant_id == "":
            print("No customer or tenant ID")
            return False
        return True

def load_alert(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    alert = AlertMessage(
        remediation=Remediation(data['remediation']['references']),
        metadata=Metadata(
            tenant_id=data['metadata']['tenant_id'],
            customer_id=data['metadata']['customer_id'],
            silent=data['metadata']['silent'],
            product=Product(
                name=data['metadata']['product']['name'],
                vendor_name=data['metadata']['product']['vendor_name'],
                version=data['metadata']['product']['version']
            ),
            analytical=data['metadata']['analytical'],
            processing_stage_time=data['metadata']['processing_stage_time'],
            labels=data['metadata']['labels']
        ),
        kill_chain=[Phase(phase=phase['phase'], phase_id=phase['phase_id']) for phase in data['kill_chain']],
        evidence=data['evidence'],
        attacks=[Attack(
            technique=AttackTechnique(attack['technique']['uid']),
            tactics=[AttackTactic(tactic['uid']) for tactic in attack['tactics']],
            version=attack['version']
        ) for attack in data['attacks']],
        time=data['time'],
        severity_id=data['severity_id'],
        message=data['message'],
        finding=Finding(
            uid=data['finding']['uid'],
            supporting_data=data['finding']['supporting_data'],
            related_events=[RelatedEvent(ds_name=event['ds_name'], uid=event['uid']) for event in data['finding']['related_events']]
        ),
        risk_level_id=data['risk_level_id'],
        analytic=Analytic(
            uid=data['analytic']['uid'],
            name=data['analytic']['name'],
            description=data['analytic']['description'],
            origin=data['analytic']['origin']
        ),
        confidence_id=data['confidence_id']
    )
    return alert

def main():
    file_path = 'alert.json'
    alert = load_alert(file_path)
    if alert.validate():
        print("Alert is valid")
    else:
        print("Alert is not valid")
    alert.build_source_list([Event(id="1", source="source1", iocs_list=[]), Event(id="2", source="source2", iocs_list=[])])
    alert.update_intel_availability([Event(id="1", source="source1", iocs_list=[]), Event(id="2", source="source2", iocs_list=["ioc1"])])
    print(alert.get_recommended_actions())

if __name__ == "__main__":
    main()