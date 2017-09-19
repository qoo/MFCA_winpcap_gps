
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
// CAboutDlg dialog used for App About

/* GPS definition */
#include "Aria.h"
#include "ArGPS.h"
#include "ArGPSConnector.h"
#include "ArTrimbleGPS.h"
#include "ArTCMCompassDirect.h"

/* Write data, read system time */
#include <iostream>
#include <fstream>
#include <string> 
#include <chrono>
using namespace std::chrono;
DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter);
DWORD WINAPI gps_CapThread(LPVOID lpParameter);

///////////////////////////////////////////[my fuction]//////////////////////////////////////////////  
//int lixsniff_initCap();
//int lixsniff_startCap();
//int lixsniff_updateTree(int index);
//int lixsniff_updateEdit(int index);
int lixsniff_updateNPacket();
//int lixsniff_saveFile();
//int lixsniff_readFile(CString path);
void getTime(char* buf);

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

int if_index, filter_index;

//HANDLE m_ThreadHandle;          //线程  
//HANDLE m_ThreadHandle2;          //线程  

std::ofstream lidarInit;
std::ofstream myfile;
char* fileLidar;
char* fileGPS;
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
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxFilter);
}

BEGIN_MESSAGE_MAP(CMFCA_winpcapDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_COMBO1, &CMFCA_winpcapDlg::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCA_winpcapDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTONHint, &CMFCA_winpcapDlg::OnBnClickedButton2)

	ON_STN_CLICKED(IDD_ABOUTBOX, &CMFCA_winpcapDlg::OnStnClickedAboutbox)
	ON_BN_CLICKED(IDOK, &CMFCA_winpcapDlg::OnBnClickedOk)
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
	/*初始化接口列表*/
	if (lixsniff_initCap()<0)
		return FALSE;
	m_comboBox.AddString(_T("0_please select the interface"));
	for (dev = alldev; dev; dev = dev->next)
	{
		if (dev->description)
			m_comboBox.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题  
	}

	//获得接口和过滤器索引  
	m_comboBox.SetCurSel(1);
	if_index = this->m_comboBox.GetCurSel();

	// get ip filter
	m_comboBoxFilter.AddString(CString("Left Lidar: 192.168.1.201"));
	m_comboBoxFilter.AddString(CString("Right Lidar: 192.168.1.202"));
	m_comboBoxFilter.SetCurSel(0);
	filter_index = this->m_comboBoxFilter.GetCurSel();
	UpdateData(FALSE);

	/*初始化接口列表*/
	//for (dev = alldev; dev; dev = dev->next)
	//{
	//	if (dev->description)
	//		m_comboBox.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题  
	//}
	//int nItem = m_listCtrl.InsertItem(3, 3);
	//m_listCtrl.SetItemText(nItem, nItem, 3);
	this->m_listCtrl.DeleteAllItems();
	m_listCtrl.InsertColumn(0, _T("No"), 3, 30);                        //1表示右，2表示中，3表示左  
	m_listCtrl.InsertColumn(1, _T("time"), 3, 130);
	m_listCtrl.InsertColumn(2, _T("length"), 3, 72);
	m_listCtrl.InsertColumn(3, _T("source MAC address"), 3, 140);
	//m_listCtrl.InsertColumn(4, _T("target MAC address"), 3, 140);
	//m_listCtrl.InsertColumn(5, _T("protocol"), 3, 70);
	//m_listCtrl.InsertColumn(6, _T("src IP"), 3, 145);
	//m_listCtrl.InsertColumn(7, _T("目的IP地址"), 3, 145);
	int nIndex = m_listCtrl.InsertItem(0, _T("1"));
	m_listCtrl.SetItemText(nIndex, 1, _T("test"));
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

void getTime(char* buf)
{
	struct tm newtime;
	__int64 ltime;
	//char buf[26];
	errno_t err;
	milliseconds ms = duration_cast<milliseconds>(
		system_clock::now().time_since_epoch()
		);
	_time64(&ltime);
	// Obtain coordinated universal time:   
	err = _gmtime64_s(&newtime, &ltime);
	err = asctime_s(buf, 26, &newtime);
}

void CMFCA_winpcapDlg::OnBnClickedButton1()
{
	// TODO: Add your control notification handler code here
	//m_EchoText.Format(_T("%d"), m_OkCount);
	//std::string test1 = std::to_string(m_OkCount);
	// MessageBoxA(NULL, test1.c_str(), "testx", MB_OK);

	this->m_listCtrl.DeleteAllItems();

	// get system time for the filename
	char buf[26];
	getTime(buf);
	buf[24] = '_';
	buf[25] = '\0';
	int i = 0;
	while (buf[i] != '\0')
	{
		if (buf[i] == ':' || buf[i] == ' ')
		{
			buf[i] = '_';
		}
		i = i + 1;
	}
	std::string str(buf);
	std::string str2(str);
	std::string str3(str);
	str += "Lidar_test.pcap";
	str2 += "GPS_test.csv";
	char *cstr = new char[str.length() + 1];
	strcpy(cstr, str.c_str());
	fileLidar = cstr;
	char *cstr2 = new char[str2.length() + 1];
	strcpy(cstr2, str2.c_str());
	fileGPS = cstr2;
	str3 += "Lidar_init.csv";
	char *cstr3 = new char[str3.length() + 1];
	strcpy(cstr3, str3.c_str());
	lidarInit.open(cstr3);
	///*初始化接口列表*/
	//m_comboBox.AddString(_T("0请选择一个网卡接口(必选)"));

	//for (dev = alldev; dev; dev = dev->next)
	//{
	//	if (dev->description)
	//		m_comboBox.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题  
	//}

	////获得接口和过滤器索引  
	//m_comboBox.SetCurSel(2);
	if_index = this->m_comboBox.GetCurSel();
	
	//// get ip filter
	//m_comboBoxFilter.AddString(CString("Left Lidar: 192.168.1.201"));
	//m_comboBoxFilter.AddString(CString("Right Lidar: 192.168.1.202"));
	//m_comboBoxFilter.SetCurSel(0);
	filter_index = this->m_comboBoxFilter.GetCurSel();

	LPDWORD threadCap = NULL;
	m_ThreadHandle = CreateThread(NULL, 0, lixsinff_CapThread, this, 0, threadCap);
	m_ThreadHandle2 = CreateThread(NULL, 0, gps_CapThread, this, 0, threadCap);


	//int argc = 1; char** argv; char *filter;
	//argv = NULL;
	//filter = "src 192.168.1.201";
	//Lidar(argc, argv, filter);
	// without UpdateData() status area will _NOT_ be updated.
	UpdateData(FALSE);
}
void CMFCA_winpcapDlg::OnBnClickedButton2()
{
	// TODO: Add your control notification handler code here
	if_index = this->m_comboBox.GetCurSel();
	std::string test1 = std::to_string(if_index);
	MessageBoxA(NULL, test1.c_str(), "Interface selection: if_index", MB_OK);
	filter_index = this->m_comboBoxFilter.GetCurSel();
	if (filter_index == 0) {
		MessageBoxA(NULL, "Left Lidar is selected", "Interface selection", MB_OK);
	}
	else if (filter_index == 1) {
		MessageBoxA(NULL, "Right Lidar is selected", "Interface selection", MB_OK);
	}
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

DWORD WINAPI gps_CapThread(LPVOID lpParameter)
{
	//MessageBox(NULL, _T("GPS is starting..."), _T("提示"), MB_OK);
	int argc = 4;// char** argv = NULL;
	//argv[0] = "-gpsBaud";
	//argv[1] = "38400";
	//argv[2] = "-gpsPort";
	//argv[3] = "COM1";
	char* argv[] = { "-gpsBaud", "38400", "-gpsPort", "COM1" };

	ArLog::log(ArLog::Normal, "Program start....");
	Aria::init();
	ArArgumentParser parser(&argc, argv);
	parser.loadDefaultArguments();
	ArRobot robot;
	ArRobotConnector robotConnector(&parser, &robot);
	ArGPSConnector gpsConnector(&parser);
	
	myfile.open(fileGPS);
	// Connect to the robot, get some initial data from it such as type and name,
	// and then load parameter files for this robot.
	//if(!robotconnector.connectrobot())
	//{
	//  arlog::log(arlog::terse, "gpsexample: warning: could not connect to robot.  will not be able to switch gps power on, or load gps options from this robot's parameter file.");
	//}

	if (!Aria::parseArgs() || !parser.checkHelpAndWarnUnparsed())
	{
		Aria::logOptions();
		ArLog::log(ArLog::Terse, "gpsExample options:\n  -printTable   Print data to standard output in regular columns rather than a refreshing terminal display, and print more digits of precision");
		MessageBox(NULL, _T("GPS parseArgs..."), _T("提示"), MB_OK);
		Aria::exit(1);
	}

	//ArLog::log(ArLog::Normal, "gpsExample: Connected to robot.");

	//robot.runAsync(true);

	//// check command line arguments for -printTable
	bool printTable = parser.checkArgument("printTable");
	//MessageBox(NULL, _T("GPS printtalble..."), _T("提示"), MB_OK);

	// On the Seekur, power to the GPS receiver is switched on by this command.
	// (A third argument of 0 would turn it off). On other robots this command is
	// ignored.
	robot.com2Bytes(116, 6, 1);
	// Try connecting to a GPS. We pass the robot pointetr to the connector so it
	// can check the robot parameters for this robot type for default values for
	// GPS device connection information (receiver type, serial port, etc.)
	ArLog::log(ArLog::Normal, "gpsExample: Connecting to GPS, it may take a few seconds...");
	ArGPS *gps = gpsConnector.createGPS(&robot);

	ArLog::log(ArLog::Terse, "save data as example.csv");
	//MessageBox(NULL, _T("GPS save example..."), _T("提示"), MB_OK);

	//myfile.open(argv[2]);
	myfile.precision(15);
	gps->printDataLabelsHeader();
	//gps->printData();
	//(gps->printData());
	//gps->haveLatitude();
	//gps->writeDataLabelsHeader();
	//printf("Pos:% 2.6f % 2.6f", gps->getLatitude(), gps->getLongitude());;
	myfile << "Latitude,Longitude,GPS time(hhmmss), System time(ms),Altitude (m),Speed (m/s),NumSatellites,AvgSNR (dB),\n";


	if (!gps || !gps->connect())
	{
		ArLog::log(ArLog::Terse, "gpsExample: Error connecting to GPS device.  Try -gpsType, -gpsPort, and/or -gpsBaud command-line arguments. Use -help for help.");
		MessageBox(NULL, _T("GPS: Error connecting to GPS device..."), _T("提示"), MB_OK);
		system("pause");
		return -1;
	}

	if (gpsConnector.getGPSType() == ArGPSConnector::Simulator)
	{
		ArLog::log(ArLog::Normal, "gpsExample: GPS data is from simulator.");
		/*
		If connected to MobileSim, and aa map is loaded into MobileSim that contains an OriginLatLonAlt line,
		then MobileSim will provides simulated GPS data based on the robot's
		true position in the simulator.  But you can also manually set "dummy"
		positions like this instead, or to simulate GPS without connecting
		to MobileSim:
		*/
		//ArLog::log(ArLog::Normal, "gpsExample: GPS is a simulator. Setting dummy position.");
		//(dynamic_cast<ArSimulatedGPS*>(gps))->setDummyPosition(42.80709, -71.579047, 100);
	}



	ArLog::log(ArLog::Normal, "gpsExample: Reading data...");
	//MessageBox(NULL, _T("GPS reading data..."), _T("提示"), MB_OK);

	ArTime lastReadTime;
	if (printTable)
	{
		ArLog::log(ArLog::Normal, "printTable is true...");
		//gps->printDataLabelsHeader();
	}

	while (true)
	{
		int r = gps->read();
		if (r & ArGPS::ReadError)
		{
			ArLog::log(ArLog::Terse, "gpsExample: Warning: error reading GPS data.");
			ArUtil::sleep(1000);
			continue;
		}


		if (r & ArGPS::ReadUpdated)
		{
			if (printTable)
			{
				gps->printData(false);
				printf("\n");
			}
			else
			{
				gps->printData();
				printf("\r");
				/* Save data to csv via following order.
				"Latitude,Longitude,System time,Altitude (m),Speed (m/s),NumSatellites,AvgSNR (dB)\n";*/
				if (!gps->havePosition())
				{
					myfile << ",";
					myfile << ",";
				}
				else
				{
					myfile << gps->getLatitude() << ",";
					myfile << gps->getLongitude() << ",";
				}
				/* time */
				myfile << gps->getGPSPositionTimestamp().getSec() << ",";
				/*system time*/
				milliseconds ms = duration_cast< milliseconds >(
					system_clock::now().time_since_epoch()
					);
				myfile << ms.count() << ",";

				if (!gps->haveAltitude())
				{
					myfile << ",";
				}
				else
				{
					myfile << gps->getAltitude() << ",";
				}
				if (gps->haveSpeed())
				{
					myfile << gps->getSpeed() << ",";
				}
				else
				{
					myfile << ",";
				}


				myfile << gps->getNumSatellitesTracked() << ",";

				if (gps->haveSNR())
				{
					myfile << gps->getMeanSNR() << ",";

				}
				else
				{
					myfile << ",";

				}
				myfile << "\n";
			}
			ArUtil::sleep(500);
			lastReadTime.setToNow();
			continue;
		}
		else {
			if (lastReadTime.secSince() >= 5) {
				ArLog::log(ArLog::Terse, "gpsExample: Warning: haven't recieved any data from GPS for more than 5 seconds!");
			}
			ArUtil::sleep(1000);
			continue;
		}

	}
	myfile.close();

	return 0;
}
DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter) 
{
	CMFCA_winpcapDlg *pthis = (CMFCA_winpcapDlg*)lpParameter;
	char* filter = "src 172.19.248.81";
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_dumper_t *dumpfile;
	/* Parameter for ex */
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	int res;
	struct tm *ltime;
	char timestr[16];
	u_char *ppkt_data;
	if (filter_index == 0) {
		filter = "src 192.168.1.201"; // "host 151.101.45.105"
		//MessageBox(NULL, _T("Left Lidar is starting..."), _T("提示"), MB_OK);
	}
	else if (filter_index == 1) {
		filter = "src 192.168.1.202"; // "host 151.101.45.105"
		//MessageBox(NULL, _T("Right Lidar is starting..."), _T("提示"), MB_OK);
	}
	else {
		MessageBox(NULL, _T("Filter IP error"), _T("提示"), MB_OK);
	}
	filter = "";
	/* Check command line */
	//if (argc != 2)
	//{
	//	printf("usage: %s filename", argv[0]);
	//	return -1;
	//}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		MessageBox(NULL, _T("Error in pcap_findalldevs:"), _T("提示"), MB_OK);
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
	inum = if_index;

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		MessageBox(NULL, _T("Interface number out of range."), _T("提示"), MB_OK);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);


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
		MessageBox(NULL, _T("Unable to open the adapter."), _T("提示"), MB_OK);
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
			MessageBox(NULL, _T("Error compiling filter: wrong syntax."), _T("提示"), MB_OK);
			pcap_close(adhandle);
			return -3;
		}
		//set the filter
		if (pcap_setfilter(adhandle, &fcode)<0)
		{
			fprintf(stderr, "\nError setting the filter\n");
			MessageBox(NULL, _T("Error setting the filter."), _T("提示"), MB_OK);
			pcap_close(adhandle);
			return -4;
		}
	}
	/* Open the dump file */
	//dumpfile = pcap_dump_open(adhandle, "test2.pcap");
	dumpfile = pcap_dump_open(adhandle, fileLidar);
	
	if (dumpfile == NULL)
	{
		MessageBox(NULL, _T("Error opening output file"), _T("提示"), MB_OK);
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}

	printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);

	/* At this point, we no longer need the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	// pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);
	/* Retrieve the packets */
	long cntLidar = 0;
	CString timestr2, buf, srcMac, destMac;
	CString lens, cntLidar_T;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* Timeout elapsed */
			continue;

		/* convert the timestamp to readable format */
		if (cntLidar < 10 || cntLidar % 1000 == 0) {
			struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt*));
			local_tv_sec = header->ts.tv_sec;
			ltime = localtime(&local_tv_sec);
			strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
			//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

			// add my code, display lidar data
			timestr2.Format(_T("%d/%d/%d  %d:%d:%d"), ltime->tm_year + 1900,
				ltime->tm_mon + 1, ltime->tm_mday, ltime->tm_hour, ltime->tm_min, ltime->tm_sec);
			//pthis->m_listCtrl.SetItemText(1,1, timestr);
			lens.Format(_T("%d"), header->len);
			cntLidar_T.Format(_T("%d"), cntLidar);
			int nIndex = pthis->m_listCtrl.InsertItem(0, cntLidar_T);
			pthis->m_listCtrl.SetItemText(nIndex, 1, timestr2);
			pthis->m_listCtrl.SetItemText(nIndex, 2, lens);
			if (cntLidar == 0) {
				/*system time*/
				milliseconds ms = duration_cast< milliseconds >(
					system_clock::now().time_since_epoch()
					);
				lidarInit << ms.count() << ",";
				lidarInit.close();
			}
		}
		cntLidar++;
		pcap_dump((unsigned char *)dumpfile, header, pkt_data);
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}


	pcap_close(adhandle);
	return 0;

}




void CMFCA_winpcapDlg::OnStnClickedAboutbox()
{
	// TODO: Add your control notification handler code here
}


void CMFCA_winpcapDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CDialogEx::OnOK();
}
