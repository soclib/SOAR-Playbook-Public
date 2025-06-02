"""
This is the example playbook developed in section 2 of the using prompts course. It uses the playbook run owner as the prompt recipient. Test run in the debugger or run manually from an event. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'review_incident' block
    review_incident(container=container)

    return

@phantom.playbook_block()
def review_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("review_incident() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """Please review this new event in SOAR and determine the severity and disposition.\nThe current event severity is {0}"""

    # parameter list for template variable replacement
    parameters = [
        "container:severity"
    ]

    # responses
    response_types = [
        {
            "prompt": "What should the severity for this event be set to?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Low",
                    "Medium",
                    "High"
                ],
            },
        },
        {
            "prompt": "What disposition action should be executed?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Monitor for new activity",
                    "Duplicate, cancel",
                    "Escalate to priority response team"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=10, name="review_incident", parameters=parameters, response_types=response_types, callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["review_incident:action_result.status", "!=", "success"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        escalate(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_severity(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def escalate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("escalate() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


@phantom.playbook_block()
def set_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity() called")

    review_incident_result_data = phantom.collect2(container=container, datapath=["review_incident:action_result.summary.responses.0"], action_results=results)

    review_incident_summary_responses_0 = [item[0] for item in review_incident_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(review_incident_summary_responses_0)
    phantom.set_severity(container, review_incident_summary_responses_0[0])

    ################################################################################
    ## Custom Code End
    ################################################################################

    decision_3(container=container)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["review_incident:action_result.summary.responses.1", "==", "Monitor for new activity"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        monitor(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["review_incident:action_result.summary.responses.1", "==", "Duplicate, cancel"]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        close(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 3
    escalate_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def monitor(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("monitor() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


@phantom.playbook_block()
def escalate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("escalate_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


@phantom.playbook_block()
def close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

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