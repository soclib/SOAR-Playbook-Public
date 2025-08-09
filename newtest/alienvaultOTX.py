"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'domain_reputation_1' block
    domain_reputation_1(container=container)

    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    parameters.append({
        'domain': "useraccount.co ",
        'section': "general",
    })

    phantom.act("domain reputation", parameters=parameters, assets=['alienvaultotx'], name="domain_reputation_1")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    parameters.append({
        'hash': "019b8a0d3f9c9c07103f82599294688b927fbbbdec7f55d853106e52cf492c2b",
    })

    phantom.act("file reputation", parameters=parameters, assets=['alienvaultotx'], name="file_reputation_1")

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    parameters.append({
        'ip': "5.224.122.45",
    })

    phantom.act("ip reputation", parameters=parameters, assets=['alienvaultotx'], name="ip_reputation_1")

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    parameters.append({
        'url': "http://wetnosesandwhiskers.com/driverfix30e45vers.exe",
    })

    phantom.act("url reputation", parameters=parameters, assets=['alienvaultotx'], name="url_reputation_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return