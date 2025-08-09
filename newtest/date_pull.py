# The purpose of this function is to pull a container creation date from a custom list in Phantom. 
# This function should work to pull any field out of a custom list in Phantom
# You can then feed the pulled date into another function to run comparisons. 

def date_pull(list_data=None, **kwargs):
    """
    Args:
        list_data
    
    Returns a JSON-serializable object that implements the configured data paths:
        qualys_date_pull
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    outputs['date_pull'] = list_data[0][0][3] #The columns of the custom function to find the date at.
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
