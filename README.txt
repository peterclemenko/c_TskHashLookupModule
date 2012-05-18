Tsk Hash Lookup Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a file analysis module that performs currently looks up a 
given file's MD5 hash value in the NSRL hash database. If the hash is found, 
the module issues a request to stop processing the file.
TODO:
 - Provide an initialization argument to determine whether or not STOP requests 
   are issued when a look up succeeds.
 - Support additional hash databases, possibly in separate modules.
 - Support notable file look ups, e.g., in user-specified EnCase hash sets. 
 - Record the look up results on the blackboard. 
 - Make a downstream module to issue stop requests after reading results 
   from the blackboard. This would allow for multiple decision making criteria
   and would support the ability to insert additional processing between the 
   look up and the decision.

USAGE

Configure the file analysis pipeline to include this module.

