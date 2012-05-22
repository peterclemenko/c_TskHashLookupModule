Tsk Hash Lookup Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a file analysis module that looks up a file's MD5 
hash value in a hash database.  Hash databases are used to identify
files that are 'known' and previously seen.  Known files can be 
both good (such as standard OS files) or bad (such as contraband).

This module currently only supports looking up files in a 
NIST NSRL database. 


USAGE

Add this module to a file analysis pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/


The module takes the path to the NSRL index file as an 
argument. See the below link for instructions on using the 
Sleuthkit's hfind tool to create an NSRL database index file.

  http://www.sleuthkit.org/informer/sleuthkit-informer-7.html#nsrl 


RESULTS

Currently, if the hash is found in the NSRL, the module
will request that the file analysis pipeline for the file
stop.


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
