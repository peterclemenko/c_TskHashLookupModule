/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file TskHashLookup.cpp
 * Contains an implementation of a hash look up file analysis module.
 * This module currently looks up a given file's MD5 hash value in the NSRL hash database.
 * If the hash is found, the module issues a request to stop processing the file.
 * TODO:
 * - Provide an initialization argument to determine whether or not STOP requests are issued
 *   when a look up succeeds.
 * - Support additional hash databases, possibly in separate modules.
 * - Support notable file look ups, e.g., in user-specified EnCase hash sets. 
 * - Record the look up results on the blackboard. 
 * - Make a downstream module to issue stop requests after reading results 
 *   from the blackboard. This would allow for multiple decision making criteria
 *   and would support the ability to insert additional processing between the 
 *   look up and the decision.
 */

// System includes
#include <sstream>

// Framework includes
#include "TskModuleDev.h"

static TSK_HDB_INFO* pHDBInfo = NULL;

extern "C" 
{
    /**
     * Module initialization function. Receives the path of a NSRL hash 
     * database index file as an intialization argument, typically read by the
     * caller from a pipeline configuration file. Returns TskModule::OK if the
     * module successfully opens the index file.  
     *
     * @param args Initialization arguments.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(std::string& args)
    {
        if (args.empty()) {
            LOGERROR(L"NSRL Lookup module passed empty argument string.");
            return TskModule::FAIL;
        }

        // Copy the arguments into a wstring. Does not convert from UTF8 to UTF16.
        std::vector<TSK_TCHAR> dbname(args.length()+1);
        std::copy(args.begin(), args.end(), dbname.begin());
        dbname[args.length()] = '\0';

        // Open the NSRL hash database index file.
        pHDBInfo = tsk_hdb_open(&dbname[0], TSK_HDB_OPEN_IDXONLY);
        if (pHDBInfo == NULL) {
            // @@@ should have TSK error message in here
            LOGERROR(L"NSRL Lookup module failed to open database");
            return TskModule::FAIL;
        }

        if (!tsk_hdb_hasindex(pHDBInfo, TSK_HDB_HTYPE_MD5_ID)) {
            LOGERROR(L"NSRL Lookup module failed to find MD5 index.");
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module execution function. Receives a pointer to a file the module is to
     * process. The file is represented by a TskFile interface which is queried
     * to get the MD5 hash of the file. The hash is then used do a look up in
     * the hash database. If the look up succeeds, a request to terminate 
     * processing of the file is issued.
     *
     * @param pFile A pointer to a file for which the hash database look up is top be performed.
     * @returns TskModule::OK on success, TskModule::FAIL on error, or TskModule::STOP if the look up succeeds.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile)
    {
        if (pFile == NULL) {
            LOGERROR(L"NSRL Lookup module passed NULL file pointer.");
            return TskModule::FAIL;
        }

        if (pHDBInfo == NULL) {
            LOGERROR(L"NSRL Lookup module not initialized.");
            return TskModule::FAIL;
        }

        try {
            std::string md5 = pFile->getHash(TskImgDB::MD5); 

            // If hash is found in database, stop further processing of file.
            if (tsk_hdb_lookup_str(pHDBInfo, md5.c_str(), TSK_HDB_FLAG_QUICK, NULL, NULL) == 1) {
                TskServices::Instance().getImgDB().updateKnownStatus(pFile->id(), TskImgDB::IMGDB_FILES_KNOWN);
                return TskModule::STOP;
            }
        }
        catch (TskException& ex) {
            std::wstringstream msg;
            msg << L"NSRL Lookup Module - Error getting hash : " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module cleanup function. This is where the module closes the NSRL hash 
     * database index file.
     *
     * @returns TskModule::OK 
     */
    TskModule::Status TSK_MODULE_EXPORT finalize() {
        if (pHDBInfo != NULL)
            tsk_hdb_close(pHDBInfo);

        return TskModule::OK;
    }
}