# Function to check if the playbook has already ran in the last seven days
# Creation date will determine flow of playbook
# The date is pulled from custom list using date_pull.py (see repository) 

def date_check(create_time=None, **kwargs): #This section of code is determined by the previous blocks in thet playbook. The variables may look different depending on artifacts 
    """
    Args:
        create_time
    
    Returns a JSON-serializable object that implements the configured data paths:
        match
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import datetime
    from datetime import datetime, timedelta, date
    
    outputs = {}
   

    try:
       
        if create_time == None:
            outputs ['match'] = 1 #The 'match' numbers will be used in the Decision block of a playbook
            

        else:
            create_time_2= create_time.split(" ")
            seven_days = datetime.strptime(create_time_2[0], "%Y-%m-%d").date() + timedelta(days=7) #Format the time in a more friendly format than UNIX time :P 
            if seven_days == datetime.today().date():
                outputs ['match'] = 2
            else:
                outputs ['match'] = 3
               

    except ValueError:
        outputs ['match'] = 3

    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
