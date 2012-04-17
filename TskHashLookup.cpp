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
 * Looks up the file's MD5 hash value in the NSRL database.
 * Current behavior (needs to change, but this is what it currently does):
 * - Supports only NSRL
 * - Stops the pipeline if the file is found in NSRL.
 * TODO:
 * - Support more than just NSRL and also support 'known bad'
 * - Set the blackboard with the lookup result. 
 * - Make another module that will stop pipeline based on NSRL lookup.
 */
// System includes
#include <windows.h>
#include <sstream>

// Framework includes
#include "TskModuleDev.h"

// Pointer to TSK hash database
static TSK_HDB_INFO * pHDBInfo = NULL;

extern "C" 
{
    /**
     * Initialization routine for NSRL lookup module. We expect to 
     * be passed the path to an MD5 index file as an argument.
     * @@@ Expand to make it support more database types.
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

            //if (tsk_hdb_makeindex(pHDBInfo, _TSK_T(TSK_HDB_DBTYPE_NSRL_MD5_STR)) == 1)
            //{
            //    LOGERROR(L"NSRL Lookup module failed creating index : " + tsk_error_get());
            //    tsk_hdb_close(pHDBInfo);
            //    pHDBInfo = NULL;

            //    return TskModule::FAIL;
            //}
        }

        return TskModule::OK;
    }

    /* Looks up hash value for file in the image datbase then then 
     * looks up in hash database.  Updates blackboard with results.
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
                TskServices::Instance().getImgDB().updateKnownStatus(pFile->id(), TskImgDB::KNOWN_STATUS::IMGDB_FILES_KNOWN);
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

    TskModule::Status TSK_MODULE_EXPORT finalize() {
        if (pHDBInfo != NULL)
            tsk_hdb_close(pHDBInfo);

        return TskModule::OK;
    }
}