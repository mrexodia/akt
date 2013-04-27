#ifndef _VF_DECODE_H
#define _VF_DECODE_H

#include "VersionFind_global.h"

/**********************************************************************
 *						Constant Defines
 *********************************************************************/
#define BACKUPKEY_NOKEYS 	0		// No Registry Keys at All
#define BACKUPKEY_NOBACKUP 	1      	// Main Key Only, No Backup Keys
#define BACKUPKEY_FIXED 	2       // Fixed Backup Keys
#define BACKUPKEY_VARIABLE 	3      	// Variable Backup Keys

#define COMPRESSION_MINIMAL	0     	// Minimal/Fastest Compression
#define COMPRESSION_BETTER 	1      	// Better/Slower Compression
#define COMPRESSION_BEST 	2       // Best/Slowest Compression

#define SPLASH_NONE 		0    	// No Splash Screen
#define SPLASH_DEFAULT 		1       // Show Default Box
#define SPLASH_BITMAP 		2	    // Show Bitmap


/**********************************************************************
 *						Type Definitions
 *********************************************************************/
typedef struct _EXTRA_OPTIONS
{
    unsigned int raw_extra_options;
    bool has_other_options; 		//For logging
    int splash_type; 				//Splash Screen Type
    bool standard_hwid; 			//Enhanced hardware ID in registration dialog
    bool enhanced_hwid; 			//Standard hardware ID in registration dialog
    bool enhanced_softice; 			//Enhanced SoftICE Detection
    bool no_clockback; 				//Don't Report Clock-Back
    bool no_clockforward; 			//Don't Report Clock-Forward
    bool screensaver_protocols; 	//Use Screen Saver Protocols
    bool disable_info; 				//Disable INFO command
    bool ignore_info; 				//Ignore INFO command
    bool disable_register; 			//Disable REGISTER command
    bool disable_unregister; 		//Disable UNREGISTER command
    bool autorevert; 				//Auto-Revert On Invalid Key
} EXTRA_OPTIONS;

typedef struct _ARMA_OPTIONS
{
    unsigned int raw_options; 		// Raw value
    char version[11]; 				// Version string
    int backupkey; 					// Backup Key Options
    int compression; 				// Compression Options
    bool nosectioncrypt; 			// Standard or Minimal?

    // Protection Options
    bool debug_blocker; 			// Debug-Blocker
    bool copymem2; 					// CopyMem2
    bool iat_elimination; 			// Enable Import Table Elimination
    bool code_splicing; 			// Enable Strategic Code Splicing
    bool nanomites; 				// Enable Nanomites Processing
    bool mem_patch_protection; 		// Enable Memory-Patching Protections

    // Other Options
    bool has_other_options;
    bool external_envvars; 			// Store Environment Vars Externally
    bool allow_one_copy; 			// Allow Only One Copy
    bool disable_monitor; 			// Disable Monitoring Thread
    bool esellerate; 				// Use eSellerate Edition Keys
    bool digital_river; 			// Use Digital River Edition Keys
    bool dontfallback; 				// Don't Fall Back to Stand-Alone Mode
    EXTRA_OPTIONS* extra_options; 	// More options
} ARMA_OPTIONS;


/**********************************************************************
 *						Prototypes
 *********************************************************************/
void FillArmaExtraOptionsStruct(unsigned int raw, EXTRA_OPTIONS* eo);
void FillArmaOptionsStruct(unsigned int raw, const char* ver, ARMA_OPTIONS* op, EXTRA_OPTIONS* eo, bool bIsMinimal);

#endif
