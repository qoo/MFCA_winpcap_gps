
// MFCA_winpcapDlg.cpp : implementation file
//

#include "stdafx.h"
#include "MFCA_winpcap.h"
#include "MFCA_winpcapDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// my
//#include <iostream>   // std::cout
//#include <stdio.h>
//#include <fstream>
//#include <chrono>
#include <string>     // std::string, std::to_string
/* Pcap definition */
#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <pcap.h>
///* prototype of the packet handler */
//int Lidar(int argc, char** argv, char *filter);
//std::ofstream lidarInit;
// CAboutDlg dialog used for App About
DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter);

///////////////////////////////////////////[my fuction]//////////////////////////////////////////////  
//int lixsniff_initCap();
//int lixsniff_startCap();
//int lixsniff_updateTree(int index);
//int lixsniff_updateEdit(int index);
int lixsniff_updateNPacket();
//int lixsniff_saveFile();
//int lixsniff_readFile(CString path);

//////////////////////////////////////////////［my data］/////////////////////////////////////////////  
int devCount;
//struct pktcount npacket;                //各类数据包计数  
char errbuf[PCAP_ERRBUF_SIZE];
pcap_if_t *alldev;
pcap_if_t *dev;
pcap_t *adhandle;
pcap_dumper_t *dumpfile;
char filepath[512];                         //  文件保存路径  
char filename[64];                          //  文件名称                              

//HANDLE m_ThreadHandle;          //线程  

								//CPtrList m_pktList;                         //捕获包所存放的链表  

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCA_winpcapDlg dialog



CMFCA_winpcapDlg::CMFCA_winpcapDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MFCA_WINPCAP_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCA_winpcapDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_comboBox);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
}

BEGIN_MESSAGE_MAP(CMFCA_winpcapDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_COMBO1, &CMFCA_winpcapDlg::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCA_winpcapDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CMFCA_winpcapDlg message handlers

BOOL CMFCA_winpcapDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	
	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	m_OkCount = 0;
	if (lixsniff_initCap()<0)
		return FALSE;

	/*初始化接口列表*/
	//for (dev = alldev; dev; dev = dev->next)
	//{
	//	if (dev->description)
	//		m_comboBox.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题  
	//}
	//int nItem = m_listCtrl.InsertItem(3, 3);
	//m_listCtrl.SetItemText(nItem, nItem, 3);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CMFCA_winpcapDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CMFCA_winpcapDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CMFCA_winpcapDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCA_winpcapDlg::OnCbnSelchangeCombo1()
{
	// TODO: Add your control notification handler code here
}


void CMFCA_winpcapDlg::OnBnClickedButton1()
{
	// TODO: Add your control notification handler code here
	m_OkCount++;
	//m_EchoText.Format(_T("%d"), m_OkCount);
	std::string test1 = std::to_string(m_OkCount);
	// MessageBoxA(NULL, test1.c_str(), "testx", MB_OK);

	LPDWORD threadCap = NULL;
	m_ThreadHandle = CreateThread(NULL, 0, lixsinff_CapThread, this, 0, threadCap);

	int argc = 1; char** argv; char *filter;
	argv = NULL;
	filter = "src 192.168.1.201";
	//Lidar(argc, argv, filter);
	// without UpdateData() status area will _NOT_ be updated.
	UpdateData(FALSE);
}

// 初始化winpcap  
int CMFCA_winpcapDlg::lixsniff_initCap()
{
	devCount = 0;
	if (pcap_findalldevs(&alldev, errbuf) == -1)
		return -1;
	for (dev = alldev; dev; dev = dev->next)
		devCount++;
	//for (dev = alldev; dev; dev = dev->next)
	//{
	//	if (dev->description)
	//		m_comboBox.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题  
	//}
	return 0;
}
int lixsniff_updateNPacket()
{
	return 0;
}
DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter) 
{
	int res, nItem;
	struct tm *ltime;
	CString timestr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;                                   //数据包头  
	const u_char *pkt_data = NULL, *pData = NULL;     //网络中收到的字节流数据  
	u_char *ppkt_data;
	CMFCA_winpcapDlg *pthis = (CMFCA_winpcapDlg*)lpParameter;
	if (NULL == pthis->m_ThreadHandle)
	{
		
		return -1;
	}
	char* filter = "src 172.19.248.81";
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;
	/* Parameter for ex */
	//struct pcap_pkthdr *header;
	//const u_char *pkt_data;
	//time_t local_tv_sec;
	//int res;
	//struct tm *ltime;
	char timestr2[16];
	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	//scanf("%d", &inum);
	inum = 2; // 1: internet 2:
	MessageBox(NULL, _T("2"), _T("提示"), MB_OK);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	MessageBox(NULL, _T("Error opening output file"), _T("提示"), MB_OK);
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/*!!! compile the filter */
	//pcap_t *fp; // pcap_t *adhandle;
	struct bpf_program fcode;
	//char *filter = NULL;
	//filter = "host 151.101.45.105";//argv[6] = "COM1";"host 52.112.64.34"
	bpf_u_int32 netmask;
	
	if (filter != NULL) {

		if (d->addresses != NULL)
			/* Retrieve the mask of the first address of the interface */
			netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		else
			/* If the interface is without an address we suppose to be in a C class network */
			netmask = 0xffffff;
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			fprintf(stderr, "\nError compiling filter: wrong syntax.\n");

			pcap_close(adhandle);
			return -3;
		}
		//set the filter
		if (pcap_setfilter(adhandle, &fcode)<0)
		{
			fprintf(stderr, "\nError setting the filter\n");

			pcap_close(adhandle);
			return -4;
		}
	}
	dumpfile = pcap_dump_open(adhandle, "test.pcap");
	if (dumpfile == NULL)
	{
		MessageBox(NULL, _T("Error opening output file"), _T("提示"), MB_OK);
		//fprintf(stderr, "\nError opening output file\n");
		return -1;
	}
	/* At this point, we no longer need the device list. Free it */
	//pcap_freealldevs(alldevs);
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)                //超时  
			continue;


		//将数据包保存到打开的文件中  
		if (dumpfile != NULL)
		{
			pcap_dump((unsigned char*)dumpfile, header, pkt_data);
		}

		//更新各类数据包计数  
		lixsniff_updateNPacket();

		//将本地化后的数据装入一个链表中，以便后来使用          
		//ppkt_data = (u_char*)malloc(header->len);
		//memcpy(ppkt_data, pkt_data, header->len);

		//pthis->m_localDataList.AddTail(data);
		//pthis->m_netDataList.AddTail(ppkt_data);

		///*预处理，获得时间、长度*/
		//data->len = header->len;                              //链路中收到的数据长度  
		//local_tv_sec = header->ts.tv_sec;
		//ltime = localtime(&local_tv_sec);
		//data->time[0] = ltime->tm_year + 1900;
		//data->time[1] = ltime->tm_mon + 1;
		//data->time[2] = ltime->tm_mday;
		//data->time[3] = ltime->tm_hour;
		//data->time[4] = ltime->tm_min;
		//data->time[5] = ltime->tm_sec;

		///*为新接收到的数据包在listControl中新建一个item*/
		//buf.Format(_T("%d"), pthis->npkt);
		//nItem = pthis->m_listCtrl.InsertItem(pthis->npkt, buf);

		///*显示时间戳*/
		//timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
		//	data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
		//pthis->m_listCtrl.SetItemText(nItem, 1, timestr);
		////pthis->m_listCtrl.setitem  

		///*显示长度*/
		//buf.Empty();
		//buf.Format(_T("%d"), data->len);
		//pthis->m_listCtrl.SetItemText(nItem, 2, buf);

		///*显示源MAC*/
		//buf.Empty();
		//buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
		//	data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
		//pthis->m_listCtrl.SetItemText(nItem, 3, buf);

		///*显示目的MAC*/
		//buf.Empty();
		//buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
		//	data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
		//pthis->m_listCtrl.SetItemText(nItem, 4, buf);

		///*获得协议*/
		//pthis->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

		///*获得源IP*/
		//buf.Empty();
		//if (0x0806 == data->ethh->type)
		//{
		//	buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
		//		data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
		//}
		//else if (0x0800 == data->ethh->type) {
		//	struct  in_addr in;
		//	in.S_un.S_addr = data->iph->saddr;
		//	buf = CString(inet_ntoa(in));
		//}
		//else if (0x86dd == data->ethh->type) {
		//	int n;
		//	for (n = 0; n<8; n++)
		//	{
		//		if (n <= 6)
		//			buf.AppendFormat(_T("%02x:"), data->iph6->saddr[n]);
		//		else
		//			buf.AppendFormat(_T("%02x"), data->iph6->saddr[n]);
		//	}
		//}
		//pthis->m_listCtrl.SetItemText(nItem, 6, buf);

		///*获得目的IP*/
		//buf.Empty();
		//if (0x0806 == data->ethh->type)
		//{
		//	buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
		//		data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
		//}
		//else if (0x0800 == data->ethh->type) {
		//	struct  in_addr in;
		//	in.S_un.S_addr = data->iph->daddr;
		//	buf = CString(inet_ntoa(in));
		//}
		//else if (0x86dd == data->ethh->type) {
		//	int n;
		//	for (n = 0; n<8; n++)
		//	{
		//		if (n <= 6)
		//			buf.AppendFormat(_T("%02x:"), data->iph6->daddr[n]);
		//		else
		//			buf.AppendFormat(_T("%02x"), data->iph6->daddr[n]);
		//	}
		//}
		//pthis->m_listCtrl.SetItemText(nItem, 7, buf);

		///*对包计数*/
		//pthis->npkt++;

	}

}
