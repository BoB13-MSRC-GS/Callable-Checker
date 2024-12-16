import sys
import os
import shutil
import configparser
import subprocess
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt5 import uic
import re

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        if getattr(sys, 'frozen', False):
            self.program_temp_directory = os.path.dirname(os.path.abspath(__file__))
        else:
            self.program_temp_directory = os.path.dirname(os.path.abspath(__file__)) + "\sfiles"
        self.program_directory = os.path.dirname(os.path.abspath(sys.executable))
        
        uic.loadUi(self.program_temp_directory + '\Main.ui', self)
        self.setFixedSize(self.size())
        
        self.idl_methods = set()
        self.idl1_methods = set()
        self.idl2_methods = set()
        self.idl3_methods = set()
        self.idl4_methods = set()
        self.idl5_methods = set()
        
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')

        self.loadConfigPaths()

        self.Service_Button.clicked.connect(self.openFileDialogForService)
        self.IDL1_Button.clicked.connect(self.openFileDialogForIDL_1)
        self.IDL2_Button.clicked.connect(self.openFileDialogForIDL_2)
        self.IDL3_Button.clicked.connect(self.openFileDialogForIDL_3)
        self.IDL4_Button.clicked.connect(self.openFileDialogForIDL_4)
        self.IDL5_Button.clicked.connect(self.openFileDialogForIDL_5)
        self.IDA_Button.clicked.connect(self.openFileDialogForIDA)
        self.Search_Button.clicked.connect(self.copyServiceFileAndExecuteCommand)

    def extract_proc_functions(self, path, idx):
        with open(path, 'r', encoding='UTF-8') as file:
            idl_content = file.read()
        pattern = r'Proc\d+_([A-Za-z0-9_]+)\('
        matches = re.findall(pattern, idl_content)
        if idx == 1:
            self.idl1_methods = set(matches)
        elif idx == 2:
            self.idl2_methods = set(matches)
        elif idx == 3:
            self.idl3_methods = set(matches)
        elif idx == 4:
            self.idl4_methods = set(matches)
        elif idx == 5:
            self.idl5_methods = set(matches)

    def remove_proc_functions(self, idx):
        if idx == 1:
            self.idl1_methods = set()
        elif idx == 2:
            self.idl2_methods = set()
        elif idx == 3:
            self.idl3_methods = set()
        elif idx == 4:
            self.idl4_methods = set()
        elif idx == 5:
            self.idl5_methods = set()
            
    def loadConfigPaths(self):
        if 'Paths' in self.config:
            if 'service_path' in self.config['Paths']:
                self.Service_Path.setText(self.config['Paths']['service_path'])
            if 'idl_path1' in self.config['Paths']:
                self.IDL1_Path.setText(self.config['Paths']['idl_path1'])
                self.extract_proc_functions(self.config['Paths']['idl_path1'], 1)
            if 'idl_path2' in self.config['Paths']:
                self.IDL2_Path.setText(self.config['Paths']['idl_path2'])
                self.extract_proc_functions(self.config['Paths']['idl_path2'], 2)
            if 'idl_path3' in self.config['Paths']:
                self.IDL3_Path.setText(self.config['Paths']['idl_path3'])
                self.extract_proc_functions(self.config['Paths']['idl_path3'], 3)
            if 'idl_path4' in self.config['Paths']:
                self.IDL4_Path.setText(self.config['Paths']['idl_path4'])
                self.extract_proc_functions(self.config['Paths']['idl_path4'], 4)
            if 'idl_path5' in self.config['Paths']:
                self.IDL5_Path.setText(self.config['Paths']['idl_path5'])
                self.extract_proc_functions(self.config['Paths']['idl_path5'], 5)
            if 'ida_path' in self.config['Paths']:
                self.IDA_Path.setText(self.config['Paths']['ida_path'])

    def saveConfigPath(self, key, value):
        if 'Paths' not in self.config:
            self.config['Paths'] = {}

        self.config['Paths'][key] = value

        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)

    def deleteConfigPath(self, key):
        if 'Paths' in self.config and key in self.config['Paths']:
            del self.config['Paths'][key]
            
            with open('config.ini', 'w') as configfile:
                self.config.write(configfile)
            
    def openFileDialogForService(self):
        fname = QFileDialog.getOpenFileName(self, '서비스 파일 선택', 'test.dll', 'DLL/EXE Files (*.dll *.exe)')[0]
        if fname:
            self.Service_Path.setText(fname)
            self.saveConfigPath('service_path', fname)
        else:
            self.Service_Path.setText("Service Path")
            self.deleteConfigPath('service_path')

    def openFileDialogForIDL_1(self):
        fname = QFileDialog.getOpenFileName(self, 'IDL 파일 선택', 'test.idl', 'IDL Files (*.idl)')[0]
        if fname:
            self.IDL1_Path.setText(fname)
            self.saveConfigPath('idl_path1', fname)
            self.extract_proc_functions(fname, 1)
        else:
            self.IDL1_Path.setText("IDL Path")
            self.deleteConfigPath('idl_path1')
            self.remove_proc_functions(1)
    
    def openFileDialogForIDL_2(self):
        fname = QFileDialog.getOpenFileName(self, 'IDL 파일 선택', 'test.idl', 'IDL Files (*.idl)')[0]
        if fname:
            self.IDL2_Path.setText(fname)
            self.saveConfigPath('idl_path2', fname)
            self.extract_proc_functions(fname, 2)
        else:
            self.IDL2_Path.setText("IDL Path")
            self.deleteConfigPath('idl_path2')
            self.remove_proc_functions(2)
            
    def openFileDialogForIDL_3(self):
        fname = QFileDialog.getOpenFileName(self, 'IDL 파일 선택', 'test.idl', 'IDL Files (*.idl)')[0]
        if fname:
            self.IDL3_Path.setText(fname)
            self.saveConfigPath('idl_path3', fname)
            self.extract_proc_functions(fname, 3)
        else:
            self.IDL3_Path.setText("IDL Path")
            self.deleteConfigPath('idl_path3')
            self.remove_proc_functions(3)
    
    def openFileDialogForIDL_4(self):
        fname = QFileDialog.getOpenFileName(self, 'IDL 파일 선택', 'test.idl', 'IDL Files (*.idl)')[0]
        if fname:
            self.IDL4_Path.setText(fname)
            self.saveConfigPath('idl_path4', fname)
            self.extract_proc_functions(fname, 4)
        else:
            self.IDL4_Path.setText("IDL Path")
            self.deleteConfigPath('idl_path4')
            self.remove_proc_functions(4)
            
    def openFileDialogForIDL_5(self):
        fname = QFileDialog.getOpenFileName(self, 'IDL 파일 선택', 'test.idl', 'IDL Files (*.idl)')[0]
        if fname:
            self.IDL5_Path.setText(fname)
            self.saveConfigPath('idl_path5', fname)
            self.extract_proc_functions(fname, 5)
        else:
            self.IDL5_Path.setText("IDL Path")
            self.deleteConfigPath('idl_path5')
            self.remove_proc_functions(5)
            

    def openFileDialogForIDA(self):
        fname = QFileDialog.getOpenFileName(self, 'IDAT 파일 선택', 'idat64.exe', 'EXE Files (*.exe)')[0]
        if fname:
            self.IDA_Path.setText(fname)
            self.saveConfigPath('ida_path', fname)
        else:
            self.IDA_Path.setText("IDAT Path")
            self.deleteConfigPath('ida_path')

    def copyServiceFileAndExecuteCommand(self):
        checked = self.RpcMethod.isChecked()
        
        service_path = self.Service_Path.text() or "Service Path"
        idl_path1 = self.IDL1_Path.text() or "IDL Path"
        idl_path2 = self.IDL2_Path.text() or "IDL Path"
        idl_path3 = self.IDL3_Path.text() or "IDL Path"
        idl_path4 = self.IDL4_Path.text() or "IDL Path"
        idl_path5 = self.IDL5_Path.text() or "IDL Path"
        ida_path = self.IDA_Path.text() or "IDAT Path"
        
        if checked:
            if service_path == "Service Path" or (idl_path1 == "IDL Path" and idl_path2 == "IDL Path" and idl_path3 == "IDL Path" and idl_path4 == "IDL Path" and idl_path5 == "IDL Path") or ida_path == "IDAT Path":
                QMessageBox.warning(self, '경고', 'Service, IDL(1개 이상), IDA 경로를 모두 설정해야 합니다.')
                return
            self.idl_methods = self.idl1_methods.union(self.idl2_methods, self.idl3_methods, self.idl4_methods, self.idl5_methods)
        else:
            if service_path == "Service Path" or ida_path == "IDAT Path":
                QMessageBox.warning(self, '경고', 'Service, IDA 경로를 설정해야 합니다.')
                return
        
        if self.Search_Edit.text() == '':
            QMessageBox.warning(self, '경고', '검색어를 입력하세요.')
            return
        
        # program_directory = os.path.dirname(os.path.abspath(__file__))
        # print(program_directory)
        workspace_directory = os.path.join(self.program_directory, 'workspace')
        if not os.path.exists(workspace_directory):
            os.makedirs(workspace_directory)
            
        script_path = os.path.join(self.program_temp_directory, 'script.py')
        
        filename = os.path.basename(service_path)
        file_basename, _ = os.path.splitext(filename)

        target_directory = os.path.join(workspace_directory, file_basename)

        service_path2 = os.path.join(target_directory, filename)
        if not os.path.exists(target_directory):
            os.makedirs(target_directory)
            shutil.copy(service_path, service_path2)

            command = f'"{ida_path}" -A -B "{service_path2}"'
            print(command)
            try:
                result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                # QMessageBox.information(self, '성공', '명령이 성공적으로 실행되었습니다.')
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, '실패', f"명령 실행 중 오류 발생:\n{e.stderr.decode()}")
                return
        
        output_path = os.path.join(target_directory, "output.txt")
        if os.path.exists(output_path):
            os.remove(output_path)
        
        service_path3 = service_path2 + ".i64"
        command = f'"{ida_path}" -A -S"{script_path} {self.Search_Edit.text()} {output_path}" "{service_path3}"'
        print(command)
        try:
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(e)
            pass
        
        if os.path.exists(output_path):
            with open(output_path, 'r') as file:
                content = file.readlines()
            
            if checked and len(self.idl_methods):
                filtered_content = [line for line in content if any(method in line for method in self.idl_methods)]
            else:
                # filtered_content = [line for line in content]
                filtered_content = content
            
            numbered_content = [f"Path {i+1}\n - {line}" for i, line in enumerate(filtered_content)]
            self.Output.setPlainText(''.join(numbered_content))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    myApp = MyApp()
    myApp.show()
    sys.exit(app.exec_())

# pyinstaller -w -F --add-data="sfiles/*;./" tool.py