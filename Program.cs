using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Permissions;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.AccessControl;

namespace WrArServ
{

    class Program
    {
        private static ConcurrentDictionary<string, bool> /*signcache*/m_cache1 = new ConcurrentDictionary<string, bool>();

        private static ConcurrentDictionary<string, int> /*illegalmax*/m_cache2 = new ConcurrentDictionary<string, int>(), /*alertcache*/m_cache3
             = new ConcurrentDictionary<string, int>();
        private static ConcurrentDictionary<string, string> /*subject sign cache*/m_cache4 = new ConcurrentDictionary<string, string>();

        private static ConcurrentDictionary<string, string> /*isinfile cache*/m_cache5 = new ConcurrentDictionary<string, string>();
        private static List<string> /*alert cache*/m_cache6 = new List<string>();

        static object lk = new object(), mlk = new object();
        static string getSubjectSign(string exefileName)
        {
            if (m_cache4.ContainsKey(exefileName))
            {
                return m_cache4[exefileName];
            }
            string sub = "";
            try
            {
                lock(lk)
                {
                    sub = PInvoke.wrSignatureSubject(exefileName);
                }
            }
            catch (Win32Exception)
            {
            }
            catch
            { }
            //   Console.WriteLine(sub);
            if (sub != "")
            {
                m_cache4.TryAdd(exefileName, sub);
            }
            return sub;
        }
        static bool isSignedExe(string exefileName)
        {
            bool isSigned = _Config.SecurityLevel == "1" ? false : true;
            if (File.Exists(exefileName))
            {
                if (m_cache1.ContainsKey(exefileName))
                {
                    isSigned = m_cache1[exefileName];
                    return isSigned;
                }
                else
                {
                    try
                    {
                        lock(lk)
                        {
                            if (PInvoke.WrIsSignedExeFile(exefileName))
                            {
                                isSigned = true;
                                //
                            }
                            else
                            {
                                isSigned = false;
                            }
                        }
                    }
                    catch
                    {
                    }
                    m_cache1.TryAdd(exefileName, isSigned);
                }
            }


            return isSigned;
        }


        static List<string> lser = new List<string>();
        static DataTable tbl;

        static bool isExcludedExe(string file1, string file2)
        {
            //List<string> lser = new List<string>();
            //var tbl = Csv.DataSetGet(dbfilename, "?", out lser);
            tbl.CaseSensitive = false;
            if (tbl.Rows.Count == 0)
                return false;
            EnumerableRowCollection<DataRow>? resulttbl = from myRow in tbl.AsEnumerable()
                                                          where myRow.Field<string>("STATE").ToLower() == "true" && myRow.Field<string>("FolderName") == "*" && (myRow.Field<string>("PermittedExeFile").ToLower() == file1.ToLower())
                                                          select myRow;
            //Console.WriteLine(1*5);
            if (resulttbl != null ? resulttbl.GetEnumerator().MoveNext() : false)
            {
                return true;
            }
            //Console.WriteLine(2*5);
            return false;
        }

        static bool isExcludedFolder(string file1, string file2)
        {
            //List<string> lser = new List<string>();
            //var tbl = Csv.DataSetGet(dbfilename, "?", out lser);
            tbl.CaseSensitive = false;
            string foldern = Path.GetDirectoryName(file2).TrimEnd('\\').ToLower();
            EnumerableRowCollection<DataRow>? resulttbl = from myRow in tbl.AsEnumerable()
                                                          where myRow.Field<string>("STATE").ToLower() == "true" && myRow.Field<string>("PermittedExeFile") == "*" && (myRow.Field<string>("FolderName").ToLower().TrimEnd('\\') == foldern)
                                                          select myRow;
            if (resulttbl != null ? resulttbl.GetEnumerator().MoveNext() : false)
                return true;

            return false;
        }

        static bool isOverridenFolder(string file1, string file2)
        {
            //List<string> lser = new List<string>();
            //var tbl = Csv.DataSetGet(dbfilename, "?", out lser);
            tbl.CaseSensitive = false;
            string foldern = Path.GetDirectoryName(file2).TrimEnd('\\').ToLower();
            EnumerableRowCollection<DataRow>? resulttbl = from myRow in tbl.AsEnumerable()
                                                          where myRow.Field<string>("STATE").ToLower() == "true" && (foldern.Contains(myRow.Field<string>("FolderName").ToLower().TrimEnd('\\')) &&
                                                          myRow.Field<string>("Subfolders").ToLower() == "true") || myRow.Field<string>("FolderName").ToLower().TrimEnd('\\') == foldern
                                                          select myRow;
            if (resulttbl != null ? resulttbl.GetEnumerator().MoveNext() : false)
                return true;

            return false;
        }

        static bool isRunAsAdmin(string file1, string file2)
        {
            bool result = false;
            //List<string> lser = new List<string>();
            //var tbl = Csv.DataSetGet(dbfilename, "?", out lser);
            tbl.CaseSensitive = false;
            string foldern = Path.GetDirectoryName(file2).TrimEnd('\\').ToLower();
            EnumerableRowCollection<DataRow>? resulttbl = from myRow in tbl.AsEnumerable()
                                                          where myRow.Field<string>("STATE").ToLower() == "true" && (foldern.Contains(myRow.Field<string>("FolderName").ToLower().TrimEnd('\\')) &&
                                                          myRow.Field<string>("Subfolders").ToLower() == "true") || myRow.Field<string>("FolderName").ToLower().TrimEnd('\\') == foldern
                                                          select myRow;
            var enumr = resulttbl.GetEnumerator();
            if (enumr.MoveNext())
                result = enumr.Current.Field<string>("RunAs").ToString().ToLower() == "true";
            return result;
        }

        static bool isOverridenSigned(string file1, string file2)
        {
            //List<string> lser = new List<string>();
            //var tbl = Csv.DataSetGet(dbfilename, "?", out lser);
            tbl.CaseSensitive = false;
            string foldern = Path.GetDirectoryName(file2).TrimEnd('\\').ToLower();
            EnumerableRowCollection<DataRow>? resulttbl = from myRow in tbl.AsEnumerable()
                                                          where myRow.Field<string>("STATE").ToLower() == "true" &&
                                                          myRow.Field<string>("OnlySigned").ToLower() == "false" &&
                                                          (foldern.Contains(myRow.Field<string>("FolderName").ToLower().TrimEnd('\\')) &&
                                                          myRow.Field<string>("Subfolders").ToLower() == "true"
                                                          || myRow.Field<string>("FolderName").ToLower().TrimEnd('\\') == foldern)
                                                          select myRow;
            if (resulttbl != null ? resulttbl.GetEnumerator().MoveNext() : false)
                return true;

            return false;
        }

        static bool isAllowedFolder(string file1, string file2)
        {
            //List<string> lser = new List<string>();
            //var tbl = Csv.DataSetGet(dbfilename, "?", out lser);
            tbl.CaseSensitive = false;
            //Console.WriteLine(file1);
            string foldern = Path.GetDirectoryName(file2).TrimEnd('\\').ToLower();
            EnumerableRowCollection<DataRow>? resulttbl = from myRow in tbl.AsEnumerable()
                                                          where myRow.Field<string>("STATE").ToLower() == "true" && foldern.Contains(myRow.Field<string>("FolderName").ToLower().TrimEnd('\\')) &&
                                                          myRow.Field<string>("Subfolders").ToLower() == "true" || myRow.Field<string>("FolderName").ToLower().TrimEnd('\\') == foldern
                                                          select myRow;
            if (resulttbl != null)
            {
                foreach (DataRow row in resulttbl)
                {
                    /*//Console.WriteLine(row["PermittedExeFile"]);
                    isSignedExe(row["PermittedExeFile"].ToString());*/
                    if (row["PermittedExeFile"].ToString().ToLower() == file1.ToLower() || row["PermittedExeFile"].ToString() == "*")
                    {
                        //           Console.WriteLine(1);

                        return true;
                    }
                }
            }
            // Console.WriteLine(2);

            return false;
        }

        static bool isInFile(string filename, string content, bool exact)
        {
            content = content.ToLower().TrimEnd('\n');
            if (!m_cache5.ContainsKey(filename))
            {
                m_cache5.TryAdd(filename, File.ReadAllText(filename, new UTF8Encoding(false)).ToLower());
            }

            foreach (var l in m_cache5[filename].Split(Environment.NewLine))
            {
                string tl = l.Trim();
                if (!String.IsNullOrWhiteSpace(content) && !String.IsNullOrWhiteSpace(tl))
                {
                    /*Console.WriteLine(content);
                    Console.WriteLine(tl);
                    Console.WriteLine(content==tl);*/
                    if (exact ? tl == content : (content.Contains(tl)))
                    {
                        return true;
                    }
                }
            }


            return false;
        }

        static bool isTheSameDir(string file1, string file2)
        {
            string dir1 = file1.Substring(0, file1.LastIndexOf('\\'));
            string dir2 = file2.Substring(0, file2.LastIndexOf('\\'));

            return dir1.ToLowerInvariant().TrimEnd('\\') == dir2.ToLowerInvariant().TrimEnd('\\');
        }

        static bool isBlkListedSignature(string exefileName)
        {
            string sub = getSubjectSign(exefileName);
            if (String.IsNullOrWhiteSpace(sub))
                return false;
            Console.WriteLine(sub);
            return isInFile($"{ System.IO.Directory.GetParent(Environment.CurrentDirectory.TrimEnd('\\')).FullName.ToLower()}\\blacklistsigns.txt", sub, true);

        }
        [MethodImpl(MethodImplOptions.Synchronized)]
        static bool IsOKAccess(string drvcont, out string log_all, out string log_delete)
        {
            log_all = log_delete = "";
            drvcont = drvcont.Trim('\n', ' ', '\t', (char)0);
            bool doUp = false;
            lock (mlk)
            {
                doUp = upDtSig;
                if (doUp)
                    upDtSig = false;
            }

            if (doUp)
            {
                Console_CancelKeyPress(null, null);

                //    Console.WriteLine(_Config.SecurityLevel);
            }

            //  

            if (_Config.SecurityLevel == "3")
                return true;


            int reserved;
            int PID;
            // Console.WriteLine(1);
            try
            {
                //Console.WriteLine("-"+drvcont);

                string rsrv = Array.Find(drvcont.ToLower().Split('\n', StringSplitOptions.RemoveEmptyEntries), a => a.StartsWith("$r")).TrimEnd((char)0).Replace("$r", "");
                if (String.IsNullOrWhiteSpace(rsrv))
                {
                    return true;
                }
                reserved = Int32.Parse(rsrv);
                // Console.WriteLine(2);
                string spid = Array.Find(drvcont.ToLower().Split('\n', StringSplitOptions.RemoveEmptyEntries), a => a.StartsWith("$p")).TrimEnd((char)0).Replace("$p", "");
                if (String.IsNullOrWhiteSpace(spid))
                    return true;
                PID = Int32.Parse(spid);
                // Console.WriteLine(3);
            }
            catch
            {
                return true;
            }
            string[] drvContent = drvcont?.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

            //MessageBox.Show(filename);                
            // Console.WriteLine(reserved);
                 //Console.WriteLine(PID);
            string exefileName = drvContent?.Length > 0 && !String.IsNullOrWhiteSpace(drvContent[0]) ? DevicePathMapper.FromDevicePath(drvContent[0]).ToLower().TrimEnd((char)0) : "";
            //    Console.WriteLine(16);
            string editfileName = drvContent?.Length > 1 && !String.IsNullOrWhiteSpace(drvContent[1]) ? DevicePathMapper.FromDevicePath(drvContent[1]).ToLower().TrimEnd((char)0).TrimEnd('\\') : "";
               // Console.WriteLine(exefileName);
             // Console.WriteLine(editfileName);
            if (exefileName == "" || editfileName == "")
                return true;
            bool isSigned = false;// _Config.SecurityLevel == "1" ? false : true;

            isSigned = isSignedExe(exefileName);
         //        Console.WriteLine(":"+isSigned);

            string exesfolder = Path.GetDirectoryName(exefileName).ToLower();
            string editsfolder = Path.GetDirectoryName(editfileName).ToLower();

            if (exesfolder.TrimEnd('\\') == Environment.CurrentDirectory.TrimEnd('\\') || exesfolder.TrimEnd('\\') == Directory.GetParent(Environment.CurrentDirectory.TrimEnd('\\')).FullName.TrimEnd('\\'))
            {
                return true;
            }

            if (_Config.SecurityLevel == "1")
            {

                bool isblk = false;
                if (isSigned)
                {
                    /* try
                     {
                         isblk = isBlkListedSignature(exefileName);
                     }
                     catch
                     { }
                    */
                    if (isblk)
                    {                    //Console.WriteLine(exefileName);

                        // Console.WriteLine("This: "+exefileName);
                        /* try
                         {
                             var ps = Process.GetProcessesByName(Path.GetFileName(exefileName).Replace(".exe", "").ToLower());
                             foreach (var p in ps)
                             {
                                 if (p.MainModule.FileName.ToLower() == exefileName)
                                 {
                                     p.Kill();
                                     File.Delete(exefileName);
                                 }
                             }

                         }
                         catch { }*/


                        return false;
                    }
                    return true;
                }
                return false;
            }
            if (!editfileName.Contains("."))
                return true;


            //  Console.WriteLine(editfileName);
            string editextension = editfileName.Substring(editfileName.LastIndexOf('.')).Trim('\n', ' ', '\t').ToLower() + ",";
            //Console.WriteLine(editextension);
            bool isoverdFolder = isOverridenFolder(exesfolder, editfileName);

             //Console.WriteLine(218+ editextension);
            if (!_Config.Proextensions.Contains(editextension))
            {
                //   Console.WriteLine(_Config.Proextensions);
                return true;
            }

//            Console.WriteLine(128);

            //   
            try
            {

                log_all += "-----\n" + exefileName + Environment.NewLine + editfileName + "\n*****";

            
            }
        catch (UnauthorizedAccessException ea)
            {
                Console.WriteLine(ea.ToString());
            }

            //          Console.WriteLine(7128);
            bool bresult = isSigned;// _Config.SecurityLevel == "1" ? false : true;
            bool isElev = false;// _Config.SecurityLevel == "1" ? false : true;
            try
            {
                isElev = PInvoke.IsElevated(PID);
            }
            catch
            { }
    //        Console.WriteLine(128);

            bool isexeWinDir = exesfolder.Contains(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            bool iseditWinDir = editsfolder.Contains(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
      //      Console.WriteLine(140);

            //   Console.WriteLine("{0} {1} {2} {3} {4}",isAllowedFolder(exefileName, editfileName), isExcludedExe(exefileName, editfileName), isExcludedFolder(exefileName, editfileName), isOverridenFolder(exefileName, editfileName), isOverridenSigned(exefileName, editfileName));
            if (isexeWinDir && iseditWinDir)
            {
                return true;
            }
        //    Console.WriteLine(1208);
            bool isconsole = isInFile($"{ System.IO.Directory.GetParent(Environment.CurrentDirectory.TrimEnd('\\')).FullName}\\consoles.lst", Path.GetFileName(exefileName).ToLower(), true);
            if (isconsole)
            {
                bresult = isElev && isSigned;
                goto Cleanup;
            }
          //  Console.WriteLine(":"+isoverdFolder);
            if (isExcludedExe(exefileName, editfileName))
            {
                bresult = true;
               // Console.WriteLine(exefileName + "*"+bresult);
            }
            else
            {
                /*isSigned = isSignedExe(exefileName);                 
                    //Console.WriteLine(isSigned);
                    if (isSigned)
                {
                    try
                    {

                      /*  bool isblkListedSign = false;
                        try
                        {
                            isblkListedSign = false;//isBlkListedSignature(exefileName);
                        }
                        catch
                        {                               
                        }
                        if (isblkListedSign)
                            return false;*/
                /*}
                catch
                { }
                //isSigned = isSigned && isblkListedSign;

            }     */
            //    Console.WriteLine(1280);
                //   Console.WriteLine("--{0} {1}", exefileName, bresult);
                if (".bat.bin.cmd.com.cpl.exe.gadget.inf1.ins.inx.isu.job.jse.lnk.msc.msi.msp.mst.paf.pif.ps1.reg.rgs.scr.sct.shb.shs.u3p.vb.vbe.vbs.vbscript.ws.wsf.wsh"
                        .Contains(editextension.TrimEnd(',')))
                {
                    bresult = isSigned;
                }
                else
                {
                    if (reserved == -255)
                    {
                        log_deletes+=exefileName + Environment.NewLine + editfileName + "\n\n";
                    
                    }
                    if (isoverdFolder)
                    {
                        if (reserved == -255)
                        {
                            bresult = isSigned && isElev;
                        }
                        //Console.WriteLine(5);
                        if (isExcludedFolder(exesfolder, editfileName))
                        {
                            bresult = true;
                        }
                        else
                        {
                            // //Console.WriteLine(6);
                            bresult = isSigned;
                            bool isalwfolder = isAllowedFolder(exesfolder, editfileName);
                            bool isoverdSign = isOverridenSigned(exesfolder, editfileName);
                            //Console.WriteLine(isSigned);
                            //Console.WriteLine(isoverdSign);
                            //Console.WriteLine(isRunAsAdmin(exesfolder, editfileName));
                            if (isoverdSign)
                            {

                                bresult = isalwfolder;
                            }
                            else
                            {
                                // bresult = isSigned;
                                if (!bresult)
                                {
                                    bresult = isalwfolder;
                                }
                            }
                            if (!isalwfolder && isRunAsAdmin(exesfolder, editfileName))
                            {
                                bresult = bresult && isElev;
                                goto Cleanup;
                            }
                        }
                    }
                    else
                    {
                        if (isTheSameDir(exefileName, editfileName))
                        {
                            if (reserved != 2)
                            {
                                bresult = true;
                            }
                            else
                            {

                                if (!m_cache2.ContainsKey(exefileName))
                                    m_cache2.TryAdd(exefileName, 1);
                                else
                                    m_cache2[exefileName]++;

                                if (m_cache2[exefileName] >= _Config.MaxIllegal)
                                    bresult = isSigned;
                               // Console.WriteLine(reserved);
                            }

                        }
                        else
                        {
                            bresult = isSigned;
                            //      Console.WriteLine(exefileName);
                            // Console.WriteLine(bresult);
                            //
                            if (reserved != 2)
                            {
                                bresult = true;
                            }
                        }


                    }
                }
            }


        // Console.WriteLine("!{0} {1}", exefileName, bresult);
        Cleanup:
            //  isAllowedFolder(exefileName, editfilename);
          // lock(mlk)
            //{
                if (!bresult && !isoverdFolder)
                {
                    if (!isSigned && isSignedExe(exefileName))
                        return true;
                    if (!m_cache6.Contains(exefileName))
                    {
                        ProcessStartInfo psi = new ProcessStartInfo($"{(AppDomain.CurrentDomain.BaseDirectory)}\\webroamransomwgui.exe", "\"" + exefileName + "\"");
                        //    psi.CreateNoWindow = true;
                        psi.UseShellExecute = false;
                        //  psi.WindowStyle = ProcessWindowStyle.Hidden;
                        psi.WorkingDirectory = Environment.CurrentDirectory;
                        Task.Run(() => Process.Start(psi));
                        m_cache6.Add(exefileName);
                    }
                    Console.WriteLine(exefileName);
                    Console.WriteLine(editfileName);
                    Console.WriteLine();
                    Console.WriteLine(isSigned);
                    Console.WriteLine("----------------------------------");
                    string textofReport = "";
                    textofReport += "------------------------------------";
                    textofReport += Environment.NewLine;
                    textofReport += "Date: " + DateTime.Now.ToString();
                    textofReport += Environment.NewLine;
                    textofReport += "Exe: " + exefileName;
                    textofReport += Environment.NewLine;
                    textofReport += "File: " + editfileName;
                    textofReport += Environment.NewLine;
                    textofReport += Environment.NewLine;
                    textofReport += "Is Exe Signed:" + isSigned;
                    textofReport += Environment.NewLine;
                    textofReport += "------------------------------------";
                    textofReport += Environment.NewLine;
                    string reportfilename = Environment.CurrentDirectory + "\\WrAR_Report.txt.wrdb";
                    try {
                        FAppendAllText(sReport, textofReport);
                    } catch { }

                    int maxsize = 5 * 1024 * 1024, maxfilecount = 10;
                    if (new FileInfo(reportfilename).Length > maxsize)
                    {
                        var outfile = File.Create(reportfilename + "_" + new Random().Next(100000) + ".zip.wrdb");
                        FileStream inFile = File.OpenRead(reportfilename);
                        using (GZipStream Compress = new GZipStream(outfile, CompressionMode.Compress))
                        {
                            // Copy the source file into 
                            // the compression stream.
                            inFile.CopyTo(Compress);
                        }
                        inFile.Close();
                        var files = Directory.EnumerateFiles(Environment.CurrentDirectory, "WrAR_Report.txt.wrdb_*");
                        if (files.Count() > maxfilecount)
                        {
                            FileSystemInfo fileInfo = new DirectoryInfo(Environment.CurrentDirectory).GetFileSystemInfos().OrderBy(f => f.CreationTime).First();
                            File.Delete(fileInfo.FullName);
                        }
                    }
                }
            //}
            return bresult;
        }
        static StreamWriter slogAll, slogDel, sReport;
        static Dictionary<string, StreamWriter> sw = new Dictionary<string, StreamWriter>();
        private static void FAppendAllText(string stream, string v)
        {/*
            using (StreamWriter sw = new StreamWriter(stream, true))
            {*/
            if (!sw.ContainsKey(stream))
            {
                sw.Add(stream, new StreamWriter(stream));
            }
                sw[stream].Write(v);
            //}
        }
        private static async void FAppendAllText(StreamWriter stream, string v)
        {
            
                await stream.WriteAsync(v);
            await stream.FlushAsync();
        }

        static bool upDtSig = false;

        static IniFile myconfig;
        struct _Config
        {
            public static string sSelfpr, Proextensions, SecurityLevel;
            public static int MaxIllegal;
            public static bool wrcheckSignature, wrDisableConsole, wrAlertBlock;

        }

        [DllImport("Kernel32")]
        private static extern bool SetConsoleCtrlHandler(EventHandler handler, bool add);

        private delegate bool EventHandler(CtrlType sig);
        static EventHandler _handler;

        enum CtrlType
        {
            CTRL_C_EVENT = 0,
            CTRL_BREAK_EVENT = 1,
            CTRL_CLOSE_EVENT = 2,
            CTRL_LOGOFF_EVENT = 5,
            CTRL_SHUTDOWN_EVENT = 6
        }

        private static bool Handler(CtrlType sig)
        {
            switch (sig)
            {
                case CtrlType.CTRL_C_EVENT:
                    //lock(mlk)
                    {
                        //  upDtSig = true;
                        string dbfilename = $"{Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'))}\\app.wrdb";

                        if (true)
                        {
                            // upDtSig = false;
                            tbl = Csv.DataSetGet(dbfilename, "?", out lser);
                            myconfig = new IniFile($"{ System.IO.Directory.GetParent(Environment.CurrentDirectory.TrimEnd('\\')).FullName}\\app_config.ini");
                            _Config.sSelfpr = myconfig.Read("SelfProtection", "RANSOME");
                            //selfProtect(_Config.sSelfpr == "1");
                            string smaxil = myconfig.Read("MaxIllegal", "RANSOME");
                            // Console.WriteLine(smaxil);

                            _Config.MaxIllegal = Int32.Parse(smaxil);

                            _Config.Proextensions = myconfig.Read("ProtectedExtensions", "RANSOME").ToLower() + ",";
                            if (!_Config.Proextensions.StartsWith("."))
                                _Config.Proextensions = "." + _Config.Proextensions;
                            _Config.wrcheckSignature = myconfig.Read("CheckCertificate", "RANSOME") == "1";
                            _Config.wrDisableConsole = myconfig.Read("DisableConsoleInFormats", "RANSOME") == "1";

                            _Config.wrAlertBlock = myconfig.Read("AlertBlock", "RANSOME") == "1";

                            _Config.SecurityLevel = myconfig.Read("SecurityLevel", "RANSOME");
                            m_cache1.Clear();
                            m_cache2.Clear();
                            m_cache4.Clear();
                            m_cache5.Clear();

                        }

                    }
                    // Console.WriteLine(sig.ToString());
                    break;
                case CtrlType.CTRL_CLOSE_EVENT:

                    break;
                case CtrlType.CTRL_LOGOFF_EVENT:
                case CtrlType.CTRL_SHUTDOWN_EVENT:
                case CtrlType.CTRL_BREAK_EVENT:
                    //  Console.WriteLine(sig.ToString());
                    break;
                default:
                    return false;
            }
            return true;
        }
        public static void CompressFile(string path)
        {
            FileStream sourceFile = File.OpenRead(path);
            FileStream destinationFile = File.Create(Path.GetDirectoryName(path)+"\\logs\\"+Path.GetFileName(path) + new Random().Next(1000000) + ".gz");

            byte[] buffer = new byte[sourceFile.Length];
            sourceFile.Read(buffer, 0, buffer.Length);

            using (GZipStream output = new GZipStream(destinationFile,
                CompressionMode.Compress))
            {


                output.Write(buffer, 0, buffer.Length);
            }

            // Close the files.
            sourceFile.Close();
            destinationFile.Close();
            File.Delete(path);
        }

        static string log_deletes = $"{(Environment.CurrentDirectory.TrimEnd('\\'))}\\log_of_deletes.wrdb";
        static string log_all = $"{(Environment.CurrentDirectory.TrimEnd('\\'))}\\log_all.wrdb";
        const int MaxPipeBufferSz = 1024 * 4;
        const string PipeName = "webroampipe";
        // static NamedPipeServerStream _pipeserver;
        // static StreamWriter strm;

        static StringBuilder strB1 = new StringBuilder(1024*16);
        static StringBuilder strB2 = new StringBuilder(1024 * 16);
        static int ops = 1;
        public static void GetMessageFromPipe()
        {
            int _lenght = 0;
            var _buffer = new byte[MaxPipeBufferSz];
            /*
             * Pipe Control Block
             */
          
              //  Console.WriteLine("hi");
                using (var _pipeserver = new NamedPipeServerStream(PipeName,
       PipeDirection.InOut, 254, PipeTransmissionMode.Message,
       PipeOptions.Asynchronous, MaxPipeBufferSz, MaxPipeBufferSz))
                {
               
                    // Console.WriteLine("hello");
                    //    strm = new StreamWriter(_pipeserver);
                    _pipeserver.WaitForConnection();
                    //Console.WriteLine("hi2");
                    do
                    {
                        _lenght += _pipeserver.Read(_buffer, _lenght, _buffer.Length);
                    }
                    while (!_pipeserver.IsMessageComplete);
                    //    Console.WriteLine("hello2");
                    //string strmsg1 = Encoding.UTF8.GetString(_buffer, 0, _lenght);
                    // Console.WriteLine(_Config.SecurityLevel);
                    /*
                    await Task.Factory.StartNew(() =>
                    {*/
                    string strmsg = Encoding.Unicode.GetString(_buffer, 0, _lenght);
                    bool isok = true;
                string slog_all = "";
                string slog_delete = "";
                try
                    {
               //     Console.WriteLine(strmsg);
                    isok = IsOKAccess(strmsg, out slog_all, out slog_delete);

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    }
                 //   Console.WriteLine(isok);
                    Array.Clear(_buffer, 0, _buffer.Length);
                    try
                    {
                        MemoryStream memoryStream = new MemoryStream(_buffer);
                        memoryStream.Write(Encoding.Unicode.GetBytes(isok.ToString()));
                        memoryStream.Flush();
                        memoryStream.Close();
                        //  
                        /*
                     }).ContinueWith((t) =>
                     {*/
                        //strm.Close();
                        _pipeserver.Write(_buffer);
                        _pipeserver.Flush();

                        _pipeserver.Disconnect();
                    //Task.Run(() =>
                    //{
                        strB1.Append(slog_all);
                        strB2.Append(slog_delete);
                        if (ops % 18 == 0)
                        {

                            // Task.Run(() =>
                            //{
                            if (log_all != "")
                            {
                                FAppendAllText(slogAll, strB1.ToString());
                            }

                            if (slog_delete != "")
                            {
                                FAppendAllText(slogDel, strB2.ToString());

                            }
                            strB1 = new StringBuilder(1024 * 16);
                            strB2 = new StringBuilder(1024 * 16);
                        }
                    ops++;
                //   }).Wait();
                }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    Environment.Exit(0);
                    }
                    //});

                
                /*
                 * End of Pipe Control Block
                 */
              
                    if (_lenght == 0)
                    {
                        _pipeserver.Disconnect();
                    Environment.Exit(0);
                    // return;
                    //throw new ArgumentException("Message is empty ;-(");
                }


                }
            }
        private static void GrantAccess(string fullPath)
        {
            DirectoryInfo dInfo = new DirectoryInfo(fullPath);
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
            dInfo.SetAccessControl(dSecurity);
            
        }

        private static void GrantAccessFile(string fullPath)
        {
            FileInfo dInfo = new FileInfo(fullPath);
            FileSecurity dSecurity = dInfo.GetAccessControl();
            dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            dInfo.SetAccessControl(dSecurity);
        }

        static void Main(string[] args)
        {
            try
            {
               /* var Procs = System.Diagnostics.Process.GetProcessesByName("WRAREngine");
                if(Procs.Length > 0)
                {
                    foreach(var p in Procs)
                    {
                        try
                        {
                            p.Kill();
                        }
                        catch { }
                    }
                }*/
                string dbfilename = $"{Directory.GetParent(Environment.CurrentDirectory.TrimEnd('\\'))}\\app.wrdb";
                tbl = null;
                // Console.WriteLine(dbfilename);
                tbl = Csv.DataSetGet(dbfilename, "?", out lser);
                //string drvCnt = "\\Device\\HarddiskVolume1\\Windows\\write.exe\n\\Device\\HarddiskVolume1\\Users\\mostafa\\desktop\\dailyPrayer\\test.txt\n";
                // _handler += new EventHandler(Handler);
                //SetConsoleCtrlHandler(_handler, true);
                // Console.CancelKeyPress += Console_CancelKeyPress;
                if(!Directory.Exists(Path.GetDirectoryName(log_all) +"\\logs"))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(log_all) +"\\logs");
                }
                if (File.Exists(log_deletes))
                     CompressFile(log_deletes);
                else
                    File.Create(log_deletes);

                if (File.Exists(log_all))
                     CompressFile(log_all);
                else
                    File.Create(log_all);
                string reportfilename = Environment.CurrentDirectory + "\\WrAR_Report.txt.wrdb";

                if (!File.Exists(reportfilename))
                    File.Create(reportfilename);

#pragma warning disable SYSLIB0003 // Type or member is obsolete
                var permissionSet = new PermissionSet(PermissionState.None);
//#pragma warning restore SYSLIB0003 // Type or member is obsolete
                var writePermission = new FileIOPermission(FileIOPermissionAccess.Write, log_all);
                permissionSet.AddPermission(writePermission);

                var writePermission2 = new FileIOPermission(FileIOPermissionAccess.Write, log_deletes);
                permissionSet.AddPermission(writePermission2);

                var writepermission3 = new FileIOPermission(FileIOPermissionAccess.Write, reportfilename);
                permissionSet.AddPermission(writepermission3);
                if(!permissionSet.IsSubsetOf(AppDomain.CurrentDomain.PermissionSet))
                {
                    Console.WriteLine("Permission Problem");
                    Console.WriteLine(Environment.CurrentDirectory);
                    GrantAccess(Environment.CurrentDirectory);
                   /* GrantAccessFile(reportfilename);
                    GrantAccessFile(log_all);
                    GrantAccessFile(log_deletes);*/
                    try
                    {
                        Console.WriteLine("Demands the permission to determine whether the application has permission to read the files");
               
                        writePermission.Demand();
                        writePermission2.Demand();
                        writepermission3.Demand();
                    }
                    catch (SecurityException s)
                    {
                        Console.WriteLine(s.Message);
                    }
                }
                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = $"{ System.IO.Directory.GetParent(Environment.CurrentDirectory.TrimEnd('\\')).FullName}";
                //Console.WriteLine(watcher.Path);
                watcher.IncludeSubdirectories = true;
                /* Watch for changes in LastAccess and LastWrite times, and 
                   the renaming of files or directories. */
                watcher.NotifyFilter = NotifyFilters.LastWrite;
                // Only watch text files.
                watcher.Filter = "*.*";
                // Add event handlers.
                watcher.Changed += new FileSystemEventHandler(OnChanged);
                // Begin watching.
                Task.Run(()
                    =>
                {
                    while (true)
                    {
                        watcher.EnableRaisingEvents = true;
                        Thread.Sleep(450);
                    }
                });
                var sPath = $"{ System.IO.Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\')).FullName}\\app_config.ini";
                //Environment.CurrentDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                myconfig = new IniFile(sPath);
                // Console.WriteLine(AppDomain.CurrentDomain.BaseDirectory);
                //  Console.WriteLine(Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\')).FullName);

                _Config.sSelfpr = myconfig.Read("SelfProtection", "RANSOME");
                //  Console.WriteLine(_Config.sSelfpr);
               // selfProtect(_Config.sSelfpr.Trim() == "1");
                string smaxil = myconfig.Read("MaxIllegal", "RANSOME");
                // Console.WriteLine(smaxil);
                if (smaxil != null)
                    _Config.MaxIllegal = Int32.Parse(smaxil.Trim());

                _Config.Proextensions = myconfig.Read("ProtectedExtensions", "RANSOME").ToLower() + ",";
                if (!_Config.Proextensions.StartsWith("."))
                    _Config.Proextensions = "." + _Config.Proextensions;
                _Config.wrcheckSignature = myconfig.Read("CheckCertificate", "RANSOME") == "1";
                _Config.wrDisableConsole = myconfig.Read("DisableConsoleInFormats", "RANSOME") == "1";

                _Config.wrAlertBlock = myconfig.Read("AlertBlock", "RANSOME") == "1";

                _Config.SecurityLevel = myconfig.Read("SecurityLevel", "RANSOME");

                slogAll = new StreamWriter(log_all, true);
                slogDel = new StreamWriter(log_deletes, true);
                sReport = new StreamWriter(reportfilename, true);
                // strm.AutoFlush = true;
                try
                    {
                    while (true)
                    {
                   
                        GetMessageFromPipe();
                    
                    }
                }
                    catch(Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    }
                slogAll.Close();
                slogDel.Close();
                foreach(var v in sw.Values)
                {
                    v.Close();
                }
               Console.WriteLine(_Config.SecurityLevel);
                //IsOKAccess(drvCnt);

                /*   int i;
                   Thread[] servers = new Thread[numThreads];


                   // //Console.WriteLine(Environment.CurrentDirectory);
                   //Console.WriteLine("Waiting for client connect...\n");
                   for (i = 0; i < numThreads; i++)
                   {
                       servers[i] = new Thread(
                           ServerThread);
                       servers[i].Start();
                   }
                   Thread.Sleep(250);
                   while (i > 0)
                   {
                       for (int j = 0; j < numThreads; j++)
                       {
                           if (servers[j] != null)
                           {
                               servers[j].Join();

                           }
                       }
                   }*/
                //Console.WriteLine("\nServer threads exhausted, exiting.");
            }
            catch (Exception em)
            { Console.WriteLine( em.Message + " " + new StackFrame(1, true).GetFileName() + " " + new StackFrame(1, true).GetFileLineNumber() + Environment.NewLine + em.ToString() + Environment.NewLine + DateTime.Now.ToString() + Environment.NewLine); }
        }
        private static void OnChanged(object sender, FileSystemEventArgs e)
        {
            //Console.WriteLine(5);
            if (e.FullPath.ToLower().Contains(".ini".ToLower()) || e.FullPath.ToLower().Contains(".wrdb".ToLower()))
            {
                //Console.WriteLine(e.FullPath);
                //Console_CancelKeyPress(null, null);
                lock (mlk)
                {
                    upDtSig = true;
                }
            }
        }

        static void selfProtect(bool bPr)
        {
            try
            {
                //    Console.WriteLine(bPr);
                var s = $"-pid {Process.GetCurrentProcess().Id} -CriticalFlag " + (bPr ? "1" : "0");
                ProcessStartInfo psi = new ProcessStartInfo($"{AppDomain.CurrentDomain.BaseDirectory}\\ProcessCritical\\ProcessCritical64.exe", s);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.WorkingDirectory = Environment.CurrentDirectory;
                Task.Run(() => Process.Start(psi)).Wait();


            }
            catch (Exception em) { FAppendAllText("wrlogS.txt.wrdb", em.Message + " " + new StackFrame(1, true).GetFileName() + " " + new StackFrame(1, true).GetFileLineNumber() + Environment.NewLine + em.ToString() + Environment.NewLine + DateTime.Now.ToString() + Environment.NewLine); }

        }
        [MethodImpl(MethodImplOptions.Synchronized)]
        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            //   e.Cancel = true;            
            //  lock(mlk)
            //upDtSig = true;

            if (true)
            {
                string dbfilename = $"{Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'))}\\app.wrdb";
                // upDtSig = false;
                tbl = Csv.DataSetGet(dbfilename, "?", out lser);
                myconfig = new IniFile($"{ System.IO.Directory.GetParent(Environment.CurrentDirectory.TrimEnd('\\')).FullName}\\app_config.ini");
                _Config.sSelfpr = myconfig.Read("SelfProtection", "RANSOME");
              //  selfProtect(_Config.sSelfpr.Trim() == "1");
                string smaxil = myconfig.Read("MaxIllegal", "RANSOME");
                //    Console.WriteLine(_Config.sSelfpr);

                _Config.MaxIllegal = Int32.Parse(smaxil);

                _Config.Proextensions = myconfig.Read("ProtectedExtensions", "RANSOME").ToLower() + ",";
                if (!_Config.Proextensions.StartsWith("."))
                    _Config.Proextensions = "." + _Config.Proextensions;
                _Config.wrcheckSignature = myconfig.Read("CheckCertificate", "RANSOME") == "1";
                _Config.wrDisableConsole = myconfig.Read("DisableConsoleInFormats", "RANSOME") == "1";

                _Config.wrAlertBlock = myconfig.Read("AlertBlock", "RANSOME") == "1";

                _Config.SecurityLevel = myconfig.Read("SecurityLevel", "RANSOME");
                m_cache1.Clear();
                m_cache2.Clear();
                m_cache4.Clear();
                m_cache5.Clear();
                Environment.Exit(0);
            }

            //  e.Cancel = true;
        }

      /*  static readonly int numThreads = 4;
        private static async void ServerThread(object data)
        {


            int threadId = Thread.CurrentThread.ManagedThreadId;

            // Wait for a client to connect


            //Console.WriteLine("Client connected on thread[{0}].", threadId);
            try
            {
                // Read the request from the client. Once the client has
                // written to the pipe its security token will be available.

                //StreamString ss = new StreamString(pipeServer);
                string str1 = "";
                // Verify our identity to the connected client using a
                // string that the client anticipates.
                // Task[] tsk = new Task[2];
                if (true)
                {
                    using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("webroampipe", PipeDirection.InOut, -1, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 1024 * 8, 1024))
                    {

                        pipeServer.WaitForConnection();
                        while (pipeServer.IsConnected)
                        {

                            byte[] rdsrc1 = new byte[1024 * 4];
                            int len = 0;

                            //     if(tsk[0] == null)





                            /*byte[] rdsrc2 = new byte[20];
                            byte[] rdsrc3 = new byte[20];*/
                            // Task.Run(() => {
                            // REREAD:
                           /* len = await pipeServer.ReadAsync(rdsrc1, 0, rdsrc1.Length);

                            if (len > 0)
                            {
                                str1 = Encoding.Unicode.GetString(rdsrc1, 0, len).Trim((char)0);

                                /*   len = pipeServer.Read(rdsrc2, 0, rdsrc2.Length);
                                   string str2 = Encoding.Unicode.GetString(rdsrc2, 0, len).Trim((char)0);

                                   len = pipeServer.Read(rdsrc3, 0, rdsrc3.Length);
                                   string str3 = Encoding.Unicode.GetString(rdsrc3, 0, len).Trim((char)0);*/

                             /*   bool isok = true;

                                try
                                {

                                    //lock (mlk)
                                    //{
                                    /* if (upDtSig)
                                     {

                                     }*/

                                    //var strd = str1.Split("$$", StringSplitOptions.RemoveEmptyEntries);
                                    // str1 = str1.Substring(str1.LastIndexOf("$$"));
                                    //  foreach (var s in strd)
                                    // {
                                    //Console.WriteLine("\\" + isok);
                                    //if (!String.IsNullOrWhiteSpace(str1))

                               /*     await Task.Run(() => isok = IsOKAccess(str1));
                                    /*if (!isok)
                                        Console.BackgroundColor = ConsoleColor.Red;*/
                                   /* Console.WriteLine(isok);
                                    //   }

                                    //    Task.WaitAll(tsk);
                                   /* try
                                    {
                                        //tsk.Wait();
                                        byte[] wsrc = Encoding.ASCII.GetBytes(isok.ToString());

                                        pipeServer.WriteAsync(wsrc, 0, wsrc.Length); //tsk?.Wait(850);
                                        pipeServer.FlushAsync();

                                     /*   Process prc = Process.GetCurrentProcess();
                                        var wallTime = DateTime.Now - prc.StartTime;
                                        if (prc.HasExited) wallTime = prc.ExitTime - prc.StartTime;
                                        var procTime = prc.TotalProcessorTime;
                                        var cpuUsage = 100 * procTime.TotalMilliseconds / wallTime.TotalMilliseconds;
                                        int mils = 500;
                                        if (cpuUsage > 26)
                                        {
                                            Thread.Sleep(mils);
                                        }
                                        else if (cpuUsage > 90)
                                        {
                                            Thread.Sleep(mils);
                                        }*/
                                  /*  }
                                    catch
                                    { }

                                    //    Console.WriteLine(str1);

                                    // 
                                }


                                //}


                                catch (Exception em) { FAppendAllText("wrlogS.txt.wrdb", em.Message + " " + new StackFrame(1, true).GetFileName() + " " + new StackFrame(1, true).GetFileLineNumber() + Environment.NewLine + em.ToString() + Environment.NewLine + DateTime.Now.ToString() + Environment.NewLine); }
                                finally
                                {




                                    //    pipeServer.WaitForPipeDrain();
                                    // if (pipeServer.IsConnected) { pipeServer.Disconnect(); }
                                }

                            }        //if(!isok)
                                     //});

                        }
                        //   //Console.WriteLine(71);
                        //   pipeServer.Flush();
                    }

                    // Read in the contents of the file while impersonating the client.
                    /*ReadFileToStream fileReader = new ReadFileToStream(ss, filename);

                     // Display the name of the user we are impersonating.
                    //Console.WriteLine("Reading file: {0} on thread[{1}] as user: {2}.",
                         filename, threadId, pipeServer.GetImpersonationUserName());
                     pipeServer.RunAsClient(fileReader.Start);*/
          /*      }
            }
            // Catch the IOException that is raised if the pipe is broken
            // or disconnected.
            catch (IOException em)
            {
                FAppendAllText("wrlogS.txt.wrdb", em.Message + " " + new StackFrame(1, true).GetFileName() + " " + new StackFrame(1, true).GetFileLineNumber() + Environment.NewLine + em.ToString() + Environment.NewLine + DateTime.Now.ToString() + Environment.NewLine);
                // Environment.Exit(1);
            }

        }*/
    }

    // Defines the data protocol for reading and writing strings on our stream


    public static class PInvoke
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("Dll1.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WrIsSignedExeFile(string filename);


        [DllImport("Dll1.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool IsElevated(int pid);


        [DllImport("Dll1.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.LPWStr)]
        public static extern string wrSignatureSubject(string lpFileName);

        public static T load_function<T>(IntPtr dll, string functionname) where T : class
        {
            IntPtr address = GetProcAddress(dll, functionname);
            System.Delegate fn_ptr = Marshal.GetDelegateForFunctionPointer(address, typeof(T));
            return fn_ptr as T;
        }

    }

    public static class DevicePathMapper
    {
        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDevice([In] string lpDeviceName, [Out] StringBuilder lpTargetPath, [In] int ucchMax);

        public static string FromDevicePath(string devicePath)
        {
            var drive = Array.Find(DriveInfo.GetDrives(), d => devicePath.StartsWith(d.GetDevicePath(), StringComparison.InvariantCultureIgnoreCase));
            return drive != null ?
                devicePath.ReplaceFirst(drive.GetDevicePath(), drive.GetDriveLetter()) :
                null;
        }
        private static ConcurrentDictionary<string, string> /*path drive cache*/m_cache6 = new ConcurrentDictionary<string, string>();
        private static string GetDevicePath(this DriveInfo driveInfo)
        {
            var devicePathBuilder = new StringBuilder(128);
            if (m_cache6.ContainsKey(driveInfo.GetDriveLetter()))
            {
                return m_cache6[driveInfo.GetDriveLetter()];
            }
            if (QueryDosDevice(driveInfo.GetDriveLetter(), devicePathBuilder, devicePathBuilder.Capacity + 1) != 0)
            {
                m_cache6.TryAdd(driveInfo.GetDriveLetter(), devicePathBuilder.ToString());
                return devicePathBuilder.ToString();
            }
            return null;
        }

        private static string GetDriveLetter(this DriveInfo driveInfo)
        {
            return driveInfo.Name.Substring(0, 2);
        }

        private static string ReplaceFirst(this string text, string search, string replace)
        {
            int pos = text.IndexOf(search);
            if (pos < 0)
            {
                return text;
            }
            return text.Substring(0, pos) + replace + text.Substring(pos + search.Length);
        }
    }

    public class Csv
    {
        public static DataTable DataSetGet(string filename, string separatorChar, out List<string> errors)
        {
            errors = new List<string>();
            var table = new DataTable("CSVTable");
            using (var sr = new StreamReader(filename, new UTF8Encoding(false)))
            {
                string line;
                var i = 0;
                while (sr.Peek() >= 0)
                {
                    try
                    {
                        line = sr.ReadLine();
                        if (string.IsNullOrEmpty(line)) continue;
                        var values = line.Split(new[] { separatorChar }, StringSplitOptions.None);
                        var row = table.NewRow();
                        for (var colNum = 0; colNum < values.Length - 1; colNum++)
                        {
                            var value = values[colNum];
                            if (i == 0)
                            {
                                table.Columns.Add(value, typeof(String));
                            }
                            else
                            {
                                row[table.Columns[colNum]] = value;
                            }
                        }
                        if (i != 0) table.Rows.Add(row);
                    }
                    catch (Exception ex)
                    {
                        // MessageBox.Show(ex.Message);
                        errors.Add(ex.Message);
                    }
                    i++;
                }
            }
            return table;
        }
    }

    class IniFile   // revision 11
    {
        string Path;
        //string EXE = Assembly.GetExecutingAssembly().GetName().Name;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern long WritePrivateProfileStringW(string Section, string Key, string Value, string FilePath);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern int GetPrivateProfileStringW(string Section, string Key, string Default, StringBuilder RetVal, int Size, string FilePath);

        public IniFile(string IniPath)
        {
            Path = new FileInfo(IniPath).FullName.ToString();
        }

        public string Read(string Key, string Section = null)
        {
            var RetVal = new StringBuilder(255);
            GetPrivateProfileStringW(Section, Key, "", RetVal, 255, Path);
            return RetVal.ToString().Trim();
        }

        public void Write(string Key, string Value, string Section = null)
        {
            WritePrivateProfileStringW(Section, Key, Value, Path);
        }

        public void DeleteKey(string Key, string Section = null)
        {
            Write(Key, null, Section);
        }

        public void DeleteSection(string Section = null)
        {
            Write(null, null, Section);
        }

        public bool KeyExists(string Key, string Section = null)
        {
            return Read(Key, Section).Length > 0;
        }
    }

    /*public static class UacHelper
    {
        private const string uacRegistryKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
        private const string uacRegistryValue = "EnableLUA";

        private static uint STANDARD_RIGHTS_READ = 0x00020000;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        public enum TOKEN_ELEVATION_TYPE
        {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        public static bool IsUacEnabled
        {
            get
            {
                using (RegistryKey uacKey = Registry.LocalMachine.OpenSubKey(uacRegistryKey, false))
                {
                    bool result = uacKey.GetValue(uacRegistryValue).Equals(1);
                    return result;
                }
            }
        }

        public static bool IsProcessElevated(IntPtr processHandle)
        {
           
                if (IsUacEnabled)
                {
                    IntPtr tokenHandle = IntPtr.Zero;
                    if (!OpenProcessToken(processHandle, TOKEN_READ, out tokenHandle))
                    {
                        throw new ApplicationException("Could not get process token.  Win32 Error Code: " +
                                                       Marshal.GetLastWin32Error());
                    }

                    try
                    {
                        TOKEN_ELEVATION_TYPE elevationResult = TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault;

                        int elevationResultSize = Marshal.SizeOf(typeof(TOKEN_ELEVATION_TYPE));
                        uint returnedSize = 0;

                        IntPtr elevationTypePtr = Marshal.AllocHGlobal(elevationResultSize);
                        try
                        {
                            bool success = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevationType,
                                                               elevationTypePtr, (uint)elevationResultSize,
                                                               out returnedSize);
                            if (success)
                            {
                                elevationResult = (TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(elevationTypePtr);
                                bool isProcessAdmin = elevationResult == TOKEN_ELEVATION_TYPE.TokenElevationTypeFull;
                                return isProcessAdmin;
                            }
                            else
                            {
                                throw new ApplicationException("Unable to determine the current elevation.");
                            }
                        }
                        finally
                        {
                            if (elevationTypePtr != IntPtr.Zero)
                                Marshal.FreeHGlobal(elevationTypePtr);
                        }
                    }
                    finally
                    {
                        if (tokenHandle != IntPtr.Zero)
                            CloseHandle(tokenHandle);
                    }
                }
                else
                {
                    WindowsIdentity identity = WindowsIdentity.GetCurrent();
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    bool result = principal.IsInRole(WindowsBuiltInRole.Administrator)
                               || principal.IsInRole(0x200); //Domain Administrator
                    return result;
                }            
        }
    }*/
}
