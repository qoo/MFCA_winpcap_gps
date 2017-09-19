
// MFCA_winpcap.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CMFCA_winpcapApp:
// See MFCA_winpcap.cpp for the implementation of this class
//

class CMFCA_winpcapApp : public CWinApp
{
public:
	CMFCA_winpcapApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CMFCA_winpcapApp theApp;