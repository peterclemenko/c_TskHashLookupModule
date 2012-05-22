TSK Hash Lookup Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


MODULE DESCRIPTION

This module is a file analysis module that looks up a given file's MD5 hash 
value in the NSRL hash database. If the hash is found, the module issues a 
request to stop processing of the file.

TODO:
 - Provide an initialization argument to specify whether or not stop requests 
   should be issued when a look up succeeds.
 - Support additional hash databases, possibly in separate modules.
 - Support notable file lookups, e.g., using user-specified EnCase hash sets. 
 - Record the lookup results on the blackboard. 
 - Make a downstream module to issue stop requests after reading results 
   from the blackboard. This would allow for multiple decision making criteria
   to be applied and would support the ability to insert additional processing 
   modules into the file analysis pipeline between the hash lookup module and 
   the decision module.

MODULE USAGE

Configure the file analysis pipeline to include this module by adding a 
"MODULE" element to the pipeline configuration file. The "arguments" attribute 
of the "MODULE" element must be set to the path of an NSRL database index file. 
See http://www.sleuthkit.org/informer/sleuthkit-informer-7.html#nsrl for 
instructions on using the Sleuthkit's hfind tool to create an NSRL database 
index file.
