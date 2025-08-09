"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_file_1() called')

    # collect data for 'detonate_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'vault_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("detonate file", parameters=parameters, assets=['virustotal'], callback=join_format_1, name="detonate_file_1")

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("url reputation", parameters=parameters, assets=['virustotal'], callback=join_format_2, name="url_reputation_1")

    return

def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_screenshot_1() called')

    # collect data for 'get_screenshot_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_screenshot_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                'size': "Medium",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("get screenshot", parameters=parameters, assets=['screenshot'], callback=decision_5, name="get_screenshot_1")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """--------------------------------------
VirusTotal調査結果
———————————————————

%%

添付ファイル名: {2}
検知数:  {0}/{1} 

%%
--------------------------------------

--------------------------------------
クラウドSandbox調査結果
———————————————————

%%

解析対象：{5}
脅威スコア：{3} / 100点
解析ステータス：{4}

%%
--------------------------------------"""

    # parameter list for template variable replacement
    parameters = [
        "detonate_file_1:action_result.summary.positives",
        "detonate_file_1:action_result.summary.total_scans",
        "detonate_file_1:artifact:*.cef.fileName",
        "detonate_file_4:action_result.data.*.threat_score",
        "detonate_file_4:action_result.status",
        "detonate_file_4:action_result.parameter.file_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_message_2(container=container)

    return

def join_format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_format_1() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'detonate_file_1', 'detonate_file_4' ]):
        
        # call connected block "format_1"
        format_1(container=container, handle=handle)
    
    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("domain reputation", parameters=parameters, assets=['virustotal'], callback=join_format_2, name="domain_reputation_1")

    return

def send_message_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_message_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_message_2' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_message_2' call
    parameters.append({
        'message': formatted_data_1,
        'destination': "#splunk-notice",
    })

    phantom.act("send message", parameters=parameters, assets=['slack'], name="send_message_2")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.vaultId", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle)
        detonate_file_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        filter_1(action=action, success=success, container=container, results=results, handle=handle)
        filter_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """不審メールのURL調査結果

--------------------------------------
URLレピュテーション結果
--------------------------------------
%%

URL: {2}
検知数: {0}/{1}

%%
--------------------------------------

--------------------------------------
ドメインレピュテーション:
--------------------------------------
%%

ドメイン名: {5}
関連する不審URL数: {3}
関連する検体のダウンロード数: {4}

%%
--------------------------------------

--------------------------------------
クラウドSandbox調査結果
--------------------------------------

%%

解析対象：{10}
脅威スコア：{6} / 100点
解析ステータス：{7}
Sandboxサービスメッセージ： {8}

%%
--------------------------------------

--------------------------------------
Get ScreenShot結果
———————————————-------
%%

URL：{11}
サービスメッセージ：{9}

%%
--------------------------------------"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_1:action_result.summary.positives",
        "url_reputation_1:action_result.summary.total_scans",
        "url_reputation_1:action_result.parameter.url",
        "domain_reputation_1:action_result.data.*.detected_communicating_samples.*.positives",
        "domain_reputation_1:action_result.data.*.detected_downloaded_samples.*.positives",
        "domain_reputation_1:action_result.parameter.domain",
        "detonate_url_1:action_result.data.*.threat_score",
        "detonate_url_1:action_result.status",
        "detonate_url_1:action_result.message",
        "get_screenshot_1:action_result.message",
        "detonate_url_1:action_result.parameter.url",
        "get_screenshot_1:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    send_message_3(container=container)

    return

def join_format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_format_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_2_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'domain_reputation_1', 'detonate_url_1', 'url_reputation_1' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_format_2_called', value='format_2')
        
        # call connected block "format_2"
        format_2(container=container, handle=handle)
    
    return

def detonate_file_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_file_4() called')

    # collect data for 'detonate_file_4' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.cef.fileName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_file_4' call
    for container_item in container_data:
        if container_item[0] and container_item[1]:
            parameters.append({
                'vault_id': container_item[0],
                'environment_id': 110,
                'file_name': container_item[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[2]},
            })

    phantom.act("detonate file", parameters=parameters, assets=['hybbrid analysis'], callback=decision_2, name="detonate_file_4")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_4:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    add_comment_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_comment_2() called')

    results_data_1 = phantom.collect2(container=container, datapath=['detonate_file_4:action_result.status'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.comment(container=container, comment=results_item_1_0)
    join_format_1(container=container)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_url_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_format_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    add_comment_3(action=action, success=success, container=container, results=results, handle=handle)

    return

def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_comment_3() called')

    results_data_1 = phantom.collect2(container=container, datapath=['detonate_url_1:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.comment(container=container, comment=results_item_1_0)
    join_format_2(container=container)

    return

def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_url_1() called')

    # collect data for 'detonate_url_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_url_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                'environment_id': 110,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("detonate url", parameters=parameters, assets=['hybbrid analysis'], callback=decision_3, name="detonate_url_1")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "not in", "custom_list:whiteurl"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        detonate_url_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        get_screenshot_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "not in", "custom_list:whitedomain"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_screenshot_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_format_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    add_comment_5(action=action, success=success, container=container, results=results, handle=handle)

    return

def add_comment_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_comment_5() called')

    results_data_1 = phantom.collect2(container=container, datapath=['get_screenshot_1:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.comment(container=container, comment=results_item_1_0)
    join_format_2(container=container)

    return

def send_message_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_message_3() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_message_3' call
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'send_message_3' call
    parameters.append({
        'message': formatted_data_1,
        'destination': "#splunk-notice",
    })

    phantom.act("send message", parameters=parameters, assets=['slack'], name="send_message_3")

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