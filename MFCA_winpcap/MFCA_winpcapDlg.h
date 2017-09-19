
// MFCA_winpcapDlg.h : header file
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
// for winpacp
//#include "afxcmn.h"  
//#include "afxwin.h"  

// CMFCA_winpcapDlg dialog
class CMFCA_winpcapDlg : public CDialogEx
{
// Construction
public:
	CMFCA_winpcapDlg(CWnd* pParent = NULL);	// standard constructor
	/////////////////////////////////////////////[my fuction]//////////////////////////////////////////////  
	int lixsniff_initCap();
	int lixsniff_startCap();
	int lixsniff_updateTree(int index);
	int lixsniff_updateEdit(int index);
	//int lixsniff_updateNPacket();
	int lixsniff_saveFile();
	int lixsniff_readFile(CString path);

	////////////////////////////////////////////////［my data］/////////////////////////////////////////////  
	//int devCount;
	////struct pktcount npacket;                //各类数据包计数  
	//char errbuf[PCAP_ERRBUF_SIZE];
	//pcap_if_t *alldev;
	//pcap_if_t *dev;
	//pcap_t *adhandle;
	//pcap_dumper_t *dumpfile;
	//char filepath[512];                         //  文件保存路径  
	//char filename[64];                          //  文件名称                              

	HANDLE m_ThreadHandle;          //线程  
	HANDLE m_ThreadHandle2;          //线程  

	//CPtrList m_pktList;                         //捕获包所存放的链表  

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCA_WINPCAP_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnBnClickedButton1();
	int m_OkCount;
	int npkt;
	CComboBox m_comboBox;
	CListCtrl m_listCtrl;


	afx_msg void OnBnClickedButton2();
	CComboBox m_comboBoxFilter;
	afx_msg void OnStnClickedAboutbox();
	afx_msg void OnBnClickedOk();
};
