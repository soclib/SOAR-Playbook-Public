"""
Demonstrates using labels in artifact data paths. Open in VPE and examine the blocks and their parameters. Note they refer to the artifacts using label names instead of the default asterisk (*). Run in debug mode in VPE with one of the &quot;File downloaded by HTTP&quot; events, which has 2 artifacts, with labels &quot;server&quot; and &quot;file&quot;.  examine the output in the debug window. Note that instead of returning a list of 2 values, which would be the default if an asterisk was used in the data path, the artifact deviceAddress CEF values are selected individually. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_1' block
    format_1(container=container)

    return

@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """\n##########################################\nServer device address: {0}.  \nFile device address: {1}\n##########################################"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:server.cef.deviceAddress",
        "artifact:file.cef.deviceAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    geolocate_ip_1(container=container)
    geolocate_ip_2(container=container)
    debug_1(container=container)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    format_1 = phantom.get_format_data(name="format_1")

    parameters = []

    parameters.append({
        "input_1": format_1,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    artifact_artifact_data = phantom.collect2(container=container, datapath=["artifact:server.cef.deviceAddress","artifact:server.id"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
    for artifact_artifact_item in artifact_artifact_data:
        if artifact_artifact_item[0] is not None:
            parameters.append({
                "ip": artifact_artifact_item[0],
                "context": {'artifact_id': artifact_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"])

    return


@phantom.playbook_block()
def geolocate_ip_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("geolocate_ip_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    artifact_artifact_data = phantom.collect2(container=container, datapath=["artifact:file.cef.deviceAddress","artifact:file.id"])

    parameters = []

    # build parameters list for 'geolocate_ip_2' call
    for artifact_artifact_item in artifact_artifact_data:
        if artifact_artifact_item[0] is not None:
            parameters.append({
                "ip": artifact_artifact_item[0],
                "context": {'artifact_id': artifact_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_2", assets=["maxmind"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return