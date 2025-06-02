"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_server_security' block
    check_server_security(container=container)

    return

@phantom.playbook_block()
def check_server_security(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_server_security() called")

    # set approver and message variables for phantom.prompt call

    message = """A security incident has occured, please check physical security for the server.\nID of the server is {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress"
    ]

    # responses
    response_types = [
        {
            "prompt": "Dooor locked",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Any issues found",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, message=message, respond_in_mins=10, name="check_server_security", parameters=parameters, response_types=response_types, callback=decision_1, dispatch_callback=check_server_security_dispatch_callback, drop_none=True)

    return


@phantom.playbook_block()
def check_server_security_dispatch_callback(container=None):
    phantom.debug("check_server_security_dispatch_callback() called")

    
    send_email_1(container=container)


    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["check_server_security:action_result.status", "==", "success"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_2(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_1() called")

    check_server_security_result_data = phantom.collect2(container=container, datapath=["check_server_security:action_result.summary.responses.1"], action_results=results)

    check_server_security_summary_responses_1 = [item[0] for item in check_server_security_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=check_server_security_summary_responses_1)

    decision_2(container=container)

    return


@phantom.playbook_block()
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Server room security has not been verified within the required time limit")

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["check_server_security:action_result.summary.responses.0", "==", "yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_4(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Door secure")

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    body_formatted_string = phantom.format(
        container=container,
        template="""Please respond to an urgent SOAR incident by clicking this link\n{0}\n""",
        parameters=[
            "check_server_security:action_result.parameter.secure_link"
        ])

    check_server_security_result_data = phantom.collect2(container=container, datapath=["check_server_security:action_result.parameter.secure_link","check_server_security:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'send_email_1' call
    for check_server_security_result_item in check_server_security_result_data:
        if body_formatted_string is not None:
            parameters.append({
                "to": "",
                "body": body_formatted_string,
                "subject": "Urgent SOAR Incident",
                "context": {'artifact_id': check_server_security_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["smtp"])

    return


@phantom.playbook_block()
def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Server room found insecure")

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