from PyQt6 import QtCore
from PyQt6.QtCore import Qt, QObject, pyqtSignal, pyqtSlot, QRunnable, QThreadPool
from PyQt6.QtWidgets import QMainWindow, QTextEdit, QFileDialog, QApplication, QWidget, QGridLayout, QLabel, QPushButton, \
                            QLineEdit, QComboBox, QProgressBar, QTableView, QDialog
from PyQt6.QtGui import QIcon, QAction
from pathlib import Path
import time
import re
import gzip
import sys
import pandas as pd
import requests
import whois
from bs4 import BeautifulSoup

class WorkerSignals(QObject):
    progress = pyqtSignal(int)

class JobRunner(QRunnable):

    signals = WorkerSignals()

    def __init__(self):
        super().__init__()

        self.is_paused = False
        self.is_killed = False

    @pyqtSlot()
    def run(self):
        nbUrls = self.data.shape[0]
        self.result = pd.DataFrame(columns=['Url', 'Match'])
        pace = 5 # wait 5 second before launching another request
        nb_matches=0

        for n in range(nbUrls):
            percent = round(n*100/nbUrls)
            self.url = self.data.iloc[n][0]

            page = requests.get(self.url)
            soup = BeautifulSoup(page.text, 'html.parser')
            for re_match in re.finditer(self.regexp, soup.prettify()):
                nb_matches = nb_matches + 1
                self.result.loc[len(self.result.index)] = [self.url,re_match.group()]

            self.qstatus.setText("<h1 style='color: white;'>Search status</h1><hr style='background-color: #bbbbbb;' /><p>Done : " + str(n+1) + " / <b>"+ str(nbUrls) +"</b></p><p>Matche(s) : " + str(nb_matches) + "</p>")
            self.signals.progress.emit(percent + 1)
            time.sleep(pace)


            while self.is_paused:
                if self.is_killed:
                    self.qstatus.setText("<h1 style='color: white;'>Search status</h1><hr style='background-color: #bbbbbb;' /><p>Done : " + str(n+1) + " / <b>"+ str(nbUrls) +"</b></p><p>Matche(s) : " + str(nb_matches) + "</p><p>Aborted !!</p>")
                    self.result.to_csv(self.outputFile)
                    return
                else:
                    time.sleep(0)

            if self.is_killed:
                self.qstatus.setText("<h1 style='color: white;'>Search status</h1><hr style='background-color: #bbbbbb;' /><p>Done : " + str(n+1) + " / <b>"+ str(nbUrls) +"</b></p><p>Matche(s) : " + str(nb_matches) + "</p><p>Aborted !!</p>")
                self.result.to_csv(self.outputFile)
                return

        self.qstatus.setText("<h1 style='color: white;'>Search status</h1><hr style='background-color: #bbbbbb;' /><p>Done : " + str(n+1) + " / <b>"+ str(nbUrls) +"</b></p><p>Matche(s) : " + str(nb_matches) + "</p><p>Finished !!</p>")
        self.result.to_csv(self.outputFile)


    def setOutputFile(self, output):
        self.outputFile = output

    def setStatus(self, qstatus):
        self.qstatus = qstatus
    
    def setData(self, data):
        self.data = data

    def setRegExp(self, regexp):
        self.regexp = regexp

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False

    def kill(self):
        self.is_killed = True

class RegexCrawlerApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'REgExp Crawler - version 0.9.3'
        self.left = 300
        self.top = 300
        self.width = 1080
        self.height = 728
        self.initUI()

    def initUI(self):
        self.mainWidget = QWidget()
        self.setCentralWidget(self.mainWidget)
        self.layout = QGridLayout()
        self.totalUrls = 0
        self.mainWidget.setLayout(self.layout)
        self.mainWidget.label_projects = QLabel(self)
        self.mainWidget.label_projects.setStyleSheet("background-color: #09152a; border: 1px solid black; color: white;")
        self.mainWidget.label_projects.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.mainWidget.label_projects.setText("<h1>Project</h1><hr style='background-color: #bbbbbb;' /><p>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  \
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</p>")
        self.mainWidget.label_status = QLabel(self)
        self.mainWidget.label_status.setStyleSheet("background-color: #09152a; border: 1px solid black; color: white;")
        self.mainWidget.label_status.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.mainWidget.label_status.setText("<h1 style='color: white;'>Search status</h1><hr style='background-color: #bbbbbb;' /><p>Done : 0 / <b>0</b></p><p>Matche(s) : 0</p>")
        self.mainWidget.label_1 = QLabel(self)
        self.mainWidget.label_1.setStyleSheet("background-image : url(GreyBackground.png); background-color: #09152a; border: 1px solid black; color: white;")
        self.mainWidget.label_1.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.mainWidget.label_1.setText("<h1>"+self.title+"</h1><hr style='background-color: #bbbbbb;' /><br /><br /><br /><br /><br />")
        self.mainWidget.regExpInput = QLineEdit(self)
        self.mainWidget.regExpInput.setStyleSheet("background-color: #030c0c; border: 1px solid black; color: white; padding: 3px; font-size: 14pt;")
        self.mainWidget.regExpInput.setText("Type your RegExp here ...")
        self.mainWidget.regExpSample = QComboBox (self)
        self.mainWidget.regExpSample.setStyleSheet("background-color: #030c0c; border: 1px solid black; color: white; padding: 3px; font-size: 14pt;")
        self.mainWidget.regExpSample.addItems(["Samples...", "Email", "IP adress", "Phone", "Visas", "Mastercard"])
        self.mainWidget.regExpSample.currentIndexChanged.connect(self.selectionchange)
        self.mainWidget.isStarted=0
        self.mainWidget.isResumed = 0
        self.mainWidget.isAborted = 0
        self.mainWidget.isProjectLoaded = 0
        self.mainWidget.startButton = QPushButton("START")
        self.mainWidget.startButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #5D8036;}")
        self.mainWidget.startButton.clicked.connect(self.startCrawling)
        self.mainWidget.stopButton = QPushButton("PAUSE")
        self.mainWidget.stopButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #CC6633;}")
        self.mainWidget.stopButton.clicked.connect(self.stopCrawling)
        self.mainWidget.abortButton = QPushButton("ABORT")
        self.mainWidget.abortButton.clicked.connect(self.abortCrawling)
        self.mainWidget.abortButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #CD3348;}")
        self.mainWidget.progress = QProgressBar()
        self.mainWidget.progress.setStyleSheet("background-color: #101d2b;")
        self.mainWidget.textEdit = QTextEdit()
        self.mainWidget.textEdit.setStyleSheet("background-color: #101d2b; color: white; font-family: Calibri; font-size: 12pt;")
        self.mainWidget.table = QTableView()
        self.mainWidget.table.setStyleSheet("background-color: #101d2b; color: white; font-family: Calibri; font-size: 12pt; height: 200px;")
        self.mainWidget.table.setDragEnabled(False)
        self.mainWidget.table.horizontalHeader().setStretchLastSection(True)
        self.mainWidget.table.resizeRowsToContents()
        self.mainWidget.table.resizeColumnsToContents()

        self.layout.addWidget(self.mainWidget.label_projects, 0, 0, 3, 1)
        self.layout.addWidget(self.mainWidget.label_status, 0, 4, 1, 1)
        self.layout.addWidget(self.mainWidget.label_1, 0, 1, 1, 3)
        self.layout.addWidget(self.mainWidget.regExpInput, 1, 1, 1, 3)
        self.layout.addWidget(self.mainWidget.regExpSample, 1, 4, 1, 1)
        self.layout.addWidget(self.mainWidget.startButton, 2, 1, 1, 1)
        self.layout.addWidget(self.mainWidget.stopButton, 2, 2, 1, 1)
        self.layout.addWidget(self.mainWidget.abortButton, 2, 3, 1, 1)
        self.layout.addWidget(self.mainWidget.progress, 2, 4, 1, 1)
        self.layout.addWidget(self.mainWidget.textEdit, 3, 0, 1, 5)
        self.layout.addWidget(self.mainWidget.table, 4, 0, 1, 5)

        self.statusBar()
        openFile = QAction(QIcon('open.png'), 'Open local Sitemap', self)
        openFile.setShortcut('Ctrl+O')
        openFile.setStatusTip('Open local Sitemap')
        openFile.triggered.connect(self.showDialog)

        openURl = QAction(QIcon('open.png'), 'Open Sitemap URL', self)
        openURl.setShortcut('Ctrl+Shift+O')
        openURl.setStatusTip('Open Sitemap URL')
        openURl.triggered.connect(self.showURL)

        exitAct = QAction(QIcon('exit.png'), 'Exit application', self)
        exitAct.setShortcut('Ctrl+Q')
        exitAct.setStatusTip('Exit application')
        exitAct.triggered.connect(QApplication.instance().quit)

        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(openFile)
        fileMenu.addAction(openURl)
        fileMenu.addAction(exitAct)

        # Thread runner
        self.mainWidget.threadpool = QThreadPool()

        # Create a runner
        self.mainWidget.runner = JobRunner()
        self.mainWidget.runner.signals.progress.connect(self.update_progress)
  
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setWindowTitle(self.title)

    def update_progress(self, n):
        self.mainWidget.progress.setValue(n)
        self.mainWidget.textEdit.setText ("Current : " + self.mainWidget.runner.url)
        self.mainWidget.model = TableModel(self.mainWidget.runner.result)
        self.mainWidget.table.setModel(self.mainWidget.model)
        

    def selectionchange(self,i):
        if i == 0:
            # Default
            self.mainWidget.regExpInput.setText("Type your RegExp here ...")
        if i == 1:
            # Email
            self.mainWidget.regExpInput.setText(r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""")
        if i == 2:
            # IP adress
            self.mainWidget.regExpInput.setText(r"([1-2]?[0-9]?[0-9]\.){3}[1-2]?[0-9]?[0-9]")
        if i == 3:
            # Phone
            self.mainWidget.regExpInput.setText(r"[0-9][0-9][./ -]?[0-9][0-9][./ -]?[0-9][0-9][./ -]?[0-9][0-9]")
        if i ==4:
            self.mainWidget.regExpInput.setText(r"4[0-9]{12,15}")
        if i ==5:
            self.mainWidget.regExpInput.setText(r"5[1-5][0-9]{14}")

    def startCrawling(self):
        if (self.mainWidget.isProjectLoaded == 1) and (self.mainWidget.regExpInput.text() != "") and (self.mainWidget.regExpInput.text() != "Type your RegExp here ...") and (self.mainWidget.isAborted != 1) : 
            if self.mainWidget.isStarted == 0:
                self.mainWidget.startButton.setStyleSheet("background-color: #5D8036; color: #FFFFFF; padding: 2px; font: bold 20px;")
                self.mainWidget.startButton.setText("STARTED")
                self.mainWidget.stopButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #CC6633;}")
                self.mainWidget.stopButton.setText("PAUSE")
                self.mainWidget.abortButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #CD3348;}")
                self.mainWidget.abortButton.setText("ABORT")
                self.mainWidget.isStarted = 1
                self.mainWidget.isResumed = 1
                self.mainWidget.textEdit.setText("")
                self.mainWidget.runner.setRegExp (self.mainWidget.regExpInput.text())
                self.mainWidget.runner.setData(self.sitemapdf)
                self.mainWidget.runner.setStatus(self.mainWidget.label_status)
                self.mainWidget.runner.setOutputFile(self.mainWidget.projectName + ".csv")
                self.mainWidget.threadpool.start(self.mainWidget.runner)
            else :
                if self.mainWidget.isResumed == 0:
                    self.mainWidget.startButton.setStyleSheet("background-color: #5D8036; color: #FFFFFF; padding: 2px; font: bold 20px;")
                    self.mainWidget.startButton.setText("RESUMED")
                    self.mainWidget.stopButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #CC6633;}")
                    self.mainWidget.stopButton.setText("PAUSE")
                    self.mainWidget.abortButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #CD3348;}")
                    self.mainWidget.abortButton.setText("ABORT")
                    self.mainWidget.isPaused = 0
                    self.mainWidget.isResumed = 1
                    self.mainWidget.runner.resume()
        else :
            self.mainWidget.textEdit.setText("Ensure a project SITEMAP is loaded and a REGEXP is set before starting")

    def stopCrawling(self):
        if self.mainWidget.isProjectLoaded == 1:
            if self.mainWidget.isResumed == 1:
                self.mainWidget.startButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #5D8036;}")
                self.mainWidget.startButton.setText("RESUME")
                self.mainWidget.stopButton.setStyleSheet("background-color: #CC6633; color: #FFFFFF; padding: 2px; font: bold 20px;")
                self.mainWidget.stopButton.setText("PAUSED")
                self.mainWidget.isResumed = 0
                self.mainWidget.runner.pause()
    
    def abortCrawling(self):
        if self.mainWidget.isProjectLoaded == 1:
            if self.mainWidget.isStarted == 1:
                self.mainWidget.startButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #5D8036;}")
                self.mainWidget.startButton.setText("START")
                self.mainWidget.stopButton.setStyleSheet("QPushButton {background-color: #0070b2; color: #FFFFFF; padding: 2px; font: bold 20px;} QPushButton:hover {background-color: #CC6633;}")
                self.mainWidget.stopButton.setText("PAUSE")
                self.mainWidget.abortButton.setStyleSheet("background-color: #CD3348; color: #FFFFFF; padding: 2px; font: bold 20px;")
                self.mainWidget.abortButton.setText("ABORTED")
                self.mainWidget.isStarted = 0
                self.mainWidget.isResumed = 0
                self.mainWidget.isAborted = 1
                self.mainWidget.runner.kill()

    def updateProjectData(self):
        self.totalUrls = self.sitemapdf.shape[0]
        self.mainWidget.label_status.setText("<h1 style='color: white;'>Search status</h1><hr style='background-color: #bbbbbb;' /><p>Done : 0 / <b>"+ str(self.totalUrls) +"</b></p><p>Matche(s) : 0</p>")
        match = re.search("https://([^/]+)/", self.sitemapdf.iloc[0][0])
        try:
            self.mainWidget.projectName = match.group(1)
        except:
            try:
                match = re.search("http://([^/]+)/", self.sitemapdf.iloc[0][0])
                self.mainWidget.projectName = match.group(1)
            except:
                self.mainWidget.projectName = self.sitemapdf.iloc[0][0]

        whoisresult = whois.whois(self.mainWidget.projectName)
        try :
            contact = whoisresult.get('emails')[0]
        except:
            contact = "Not found"
        #print (whoisresult)
        self.mainWidget.label_projects.setText("<h1>Project</h1><hr style='background-color: #bbbbbb;' />\n \
        <p><b>Web site : </b>"+ self.mainWidget.projectName +"</p>\n \
        <p><b>Domain : </b>"+ whoisresult.domain +"</p>\n \
        <p><b>Creation date : </b>"+ str(whoisresult.get('creation_date')) +"</p>\n \
        <p><b>Expiration date : </b>"+ str(whoisresult.get('expiration_date')) +"</p>\n \
        <p><b>Name server : </b>"+ whoisresult.get('name_servers')[0]+"</p>\n \
        <p><b>Contact : </b>"+ contact +"</p>\n \
        ")
        self.mainWidget.isProjectLoaded = 1
        self.mainWidget.runner.setData(self.sitemapdf)

    def showDialog(self):
        self.sitemapUrl= "file:///"
        filters = "Xml files (*.xml);;Text files (*.txt);;Any files (*)"
        home_dir = str(Path.home())
        fname = QFileDialog.getOpenFileName(self, 'Open local Sitemap', home_dir, filters)

        if fname[0]:
            self.sitemapUrl += fname[0]
            self.sitemapdf = self.parse_sitemap()
            self.updateProjectData()
            
    def showURL(self):
        self.URLDialog = QDialog(self)
        self.URLDialog.setWindowTitle('Open Sitemap from URL')
        URLGoButton = QPushButton("Go !")
        self.URLGoInput = QLineEdit("")
        URLGoLabel = QLabel("Input Sitemap URL :")
        layout = QGridLayout()
        self.URLDialog.setLayout(layout)
        layout.addWidget(URLGoLabel, 0, 0, 1, 1)
        layout.addWidget(self.URLGoInput, 0, 1, 1, 1)
        layout.addWidget(URLGoButton, 0, 2, 1, 1)
        self.URLDialog.resize(480, 120)
        URLGoButton.clicked.connect(self.openURLAndClose)
        self.URLDialog.exec()
    
    def openURLAndClose(self):
        self.sitemapUrl= self.URLGoInput.text()
        self.URLDialog.accept()
        if self.sitemapUrl:
            self.sitemapdf = self.parse_sitemap()
            self.updateProjectData()         
    
    def parse_sitemap(self, **kwargs):
        sitemap = self.sitemapUrl
        urls = pd.DataFrame()
        if sitemap[:4] == "file":
        # local access
#            print("local access : " + sitemap[:4])
            f = open(sitemap[8:], 'r', encoding='utf-8')
            with f:
                content = f.read()
        else:
        # distant access
            resp = requests.get(sitemap, **kwargs)
            if not resp.ok:
                print(f'Unable to fetch sitemap. Request returned HTTP Response {resp.status_code}. Please check your input.')
                return None
            if resp.headers['Content-Type'] == 'application/x-gzip':
                content = gzip.decompress(resp.content)
            else:
                content = resp.content
        soup = BeautifulSoup(content, 'xml')
        if soup.select('sitemapindex'):
            sitemaps = pd.read_xml(content)
            for each_sitemap in sitemaps['loc'].tolist():
                resp = requests.get(each_sitemap, **kwargs)
                if resp.ok:
                    if resp.headers['Content-Type'] == 'application/x-gzip':
                        content = gzip.decompress(resp.content)
                    else:
                        content = resp.content
                    urls = pd.concat([urls, pd.read_xml(content)])
                else:
                    print(f'Unable to fetch {each_sitemap}. Request returned HTTP Response {resp.status_code}.')
        else:
            urls = pd.read_xml(content)
        return urls

class TableModel(QtCore.QAbstractTableModel):

    def __init__(self, data):
        super(TableModel, self).__init__()
        self._data = data

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            value = self._data.iloc[index.row(), index.column()]
            return str(value)

    def rowCount(self, index):
        return self._data.shape[0]

    def columnCount(self, index):
        return self._data.shape[1]

    def headerData(self, section, orientation, role):
        # section is the index of the column/row.
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal:
                return str(self._data.columns[section])

            if orientation == Qt.Orientation.Vertical:
                return str(self._data.index[section])


app = QApplication(sys.argv)
#path = r"C:/Python/projets/testPyQT"
#app.addLibraryPath(path)
regExApp = RegexCrawlerApp()
regExApp.show()
app.exec()