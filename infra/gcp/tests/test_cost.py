import datetime as dt
import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('lab',Path(__file__).resolve().parents[1]/'lab.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)

class Cost(unittest.TestCase):
    def setUp(self):
        self.now=dt.datetime(2026,10,19,tzinfo=dt.timezone.utc)
        self.configuration={'expires_at':(self.now+dt.timedelta(hours=4)).isoformat()}
    def test_window_reserves_cleanup_and_does_not_assume_free_tier(self):
        self.assertEqual(lab.estimate(self.configuration,{},self.now)['modeled_total_including_reserves_usd'],7)
    def test_expired_or_unbounded_windows_refused(self):
        for hours in [0,-1,4.01,100]:
            with self.assertRaises(ValueError): lab.estimate({'expires_at':(self.now+dt.timedelta(hours=hours)).isoformat()},{},self.now)
    def test_retries_count_prior_allocations(self):
        with self.assertRaises(ValueError): lab.estimate(self.configuration,{'retired_cost_upper_bound_usd':3.01},self.now)
    def test_extending_does_not_reset_the_campaign_clock(self):
        ledger={'first_paid_start':(self.now-dt.timedelta(hours=4)).isoformat()}
        with self.assertRaises(ValueError): lab.estimate(self.configuration,ledger,self.now)
    def test_invalid_history_refused(self):
        for value in [-1,float('nan'),float('inf')]:
            with self.assertRaises(ValueError): lab.estimate(self.configuration,{'retired_cost_upper_bound_usd':value},self.now)

class Plan(unittest.TestCase):
    def setUp(self):
        self.config={'project_id':'tds-rust-auth-test','expires_at':'2026-10-19T04:00:00Z','client_cidr':'192.0.2.1/32'}
        self.value={'project':self.config['project_id'],'machine_type':'e2-standard-2',
                    'scheduling':[{'termination_time':self.config['expires_at'],'instance_termination_action':'DELETE'}],
                    'boot_disk':[{'auto_delete':True,'initialize_params':[{'type':'pd-standard','size':64,'image':'https://www.googleapis.com/compute/v1/projects/windows-cloud/global/images/windows-2022'}]}],
                    'network_interface':[{'access_config':[{}]}],'service_account':[{'scopes':[]}]}
    def plan(self,value=None,kind='google_compute_instance'):
        return {'resource_changes':[{'type':kind,'change':{'after':value if value is not None else self.value}}]}
    def test_priced_plan_is_accepted(self):
        self.assertEqual(lab.validate_plan(self.plan(),self.config),1)
    def test_bigger_vm_wrong_project_or_missing_expiry_refused(self):
        for key,value in [('machine_type','e2-standard-32'),('project','catchupwithhcd-prod'),('scheduling',[{'instance_termination_action':'STOP','termination_time':self.config['expires_at']}])]:
            modified=copy.deepcopy(self.value);modified[key]=value
            with self.assertRaises(ValueError):lab.validate_plan(self.plan(modified),self.config)
    def test_retained_or_unpriced_disk_refused(self):
        for auto,kind,size in [(False,'pd-standard',64),(True,'pd-ssd',64),(True,'pd-standard',1000)]:
            modified=copy.deepcopy(self.value);modified['boot_disk'][0]['auto_delete']=auto
            modified['boot_disk'][0]['initialize_params'][0].update(type=kind,size=size)
            with self.assertRaises(ValueError):lab.validate_plan(self.plan(modified),self.config)
    def test_unpriced_resource_type_and_open_ingress_refused(self):
        with self.assertRaises(ValueError):lab.validate_plan(self.plan(kind='google_compute_router_nat'),self.config)
        with self.assertRaises(ValueError):lab.validate_plan(self.plan({'project':self.config['project_id'],'source_ranges':['0.0.0.0/0']},'google_compute_firewall'),self.config)
    def test_replacements_and_deletions_refused_even_if_after_values_are_safe(self):
        for actions in [['delete','create'],['create','delete'],['delete']]:
            plan=self.plan();plan['resource_changes'][0]['change']['actions']=actions
            with self.assertRaises(ValueError):lab.validate_plan(plan,self.config)

if __name__=='__main__': unittest.main()
