// 
// Project : RemoveCertificate
// Supprimer les certificats authenticode des Portable Executable
// 2012 - Nicolas.GOLLET    <at>   nginfo.fr
//
//



using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

using NDesk.Options;

namespace RemoveCertificate
{
    class Program
    {

        static int verbosity;
        
        public const short INVALID_HANDLE_VALUE = -1;
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint OPEN_EXISTING = 3;
        public const uint CERT_SECTION_TYPE_ANY = 255;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("Imagehlp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ImageEnumerateCertificates(IntPtr hFile, uint wTypeFilter,
            ref uint dwCertCount, IntPtr pIndices, IntPtr pIndexCount);

        [DllImport("Imagehlp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ImageRemoveCertificate(IntPtr hFile, uint dwCertCount);


        static Boolean RemoveCert(string filename)
        {
            

   
               


            try {


                IntPtr hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

                if (hFile.ToInt32() == -1)
                {
                    /* ask the framework to marshall the win32 error code to an exception */
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
                else
                {
                 
                    
                    // First test Have certificate?

                    uint certCount = 0;
                    if (!ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, ref certCount, IntPtr.Zero, IntPtr.Zero))
                    {
                        Console.WriteLine("\t *" + filename + " is not a PE32/64 signed file.");
                        return false;
                    }

                    // controle si il y a des certificats
                    if (certCount == 0)
                    {
                        Console.WriteLine("\t *" + filename + " NOT have Authenticode.");
                        return false;
                    }


                    while (true)
                    {
                        certCount = 0;
                        if (!ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, ref certCount, IntPtr.Zero, IntPtr.Zero))
                        {
                            Console.WriteLine("\t *" + filename + " is not a PE32/64 singed file.");
                            break;
                        }

                        // controle si il y a des certificats
                        if (certCount == 0)
                        {
                            break;
                        }
                        for (uint certIndex = 0; certIndex < certCount; certIndex++)
                        {
                            if (!ImageRemoveCertificate(hFile, certIndex))
                            {
                                CloseHandle(hFile);
                                Console.WriteLine("\t *" + filename + " =ERROR=> Cert NOT removed. ("+ certIndex.ToString() + ")");
                                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                            }
                        }

                        Console.WriteLine("\t *" + filename + " =OK=> Cert removed succeeded.");
                    }

                    CloseHandle(hFile);
                }
            }
            catch (Exception e){
                DebugPrint(filename  +" =ERROR=> message {0} ", e.ToString());
                return false;
            }           
                
                return true;


         }

        // help
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: RemoveCertificate [OPTIONS]+");
            Console.WriteLine("Remove Authenticode from Windows Executable (PE32/PE64)");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static void DebugPrint(string format, params object[] args)
        {
            if (verbosity > 0)
            {
                Console.Write("# ");
                Console.WriteLine(format, args);
            }
        }



        // start :
        static void Main(string[] args)
        {
            bool show_help = false;
            bool recur = false;

         

            List<string> names = new List<string>();
            List<string> directories = new List<string>();
            var p = new OptionSet() {
            { "f|file=", "Remove authenticode from {FILE}\nWildcare char is allow",
              v => names.Add (v) },
            { "d|directory=", "{DIRECTORY} directory to scan\nUsing with wildcare char",
              v => directories.Add (v) },
            { "r", 
                "Search recursivity (used with directory)",
                 v => { if (v != null) recur=true; } },
            { "v", "increase debug message verbosity",
              v => { if (v != null) ++verbosity; } },
            { "h|help",  "show this message and exit", 
              v => show_help = v != null },
            };

            if (args.Count() < 1)
            {

                ShowHelp(p);
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();

                Environment.Exit(2);

            }


            Console.WriteLine("Authenticode Removal");
            Console.WriteLine("version 1.0");

            List<string> extra;
            try
            {
                extra = p.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("RemoveCertificate: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try `RemoveCertificate --help' for more information.");
                return;
            }

            if (show_help)
            {
                ShowHelp(p);
                return;
            }

            string message;
            if (extra.Count > 0)
            {
                message = string.Join(" ", extra.ToArray());
                DebugPrint("Using file parser: {0}", message);
            }


            foreach (string name in names)
            {
                Console.Write("Processing {0}", name);
                if (name.Contains("*"))
                {
                    Console.WriteLine(" (wildcare)");

                    DebugPrint("\tWildcare mode (*)");
                    if (directories.Count() > 0)
                    {

                        foreach (string dir in directories)
                        {
                            DebugPrint("\tApply in {0} directory", dir);

                            if (Directory.Exists(dir))
                            {

                                DebugPrint("{0} exist", dir);

                                SearchOption sorecursiv;
                                if (recur == true)
                                {
                                    sorecursiv = SearchOption.AllDirectories;
                                    DebugPrint("recursive : {0}", recur);
                                }
                                else
                                {
                                    sorecursiv = SearchOption.TopDirectoryOnly;
                                    DebugPrint("recursive : {0}", recur);
                                }

                                string[] filesSearchList = Directory.GetFiles(dir, name, sorecursiv);

                                // Display all the files.
                                foreach (string fileSearch in filesSearchList)
                                {
                                    DebugPrint("Remove Cert => : {0}", fileSearch);
                                    if (RemoveCert(fileSearch) == true)
                                    {
                                        DebugPrint("RemoveCert({0}) => TRUE", fileSearch);
                                    }
                                    else
                                    {
                                        DebugPrint("RemoveCert({0}) => FALSE", fileSearch);
                                    }
                                }

                            }

                        }
                    }
                    else
                    {
                        Console.WriteLine("No directory option, Wildcare ignored. (use wildcare with Directory option)");
                    }


                }
                else
                {
                    DebugPrint("File mode");
                     // test si fichier valide :
                    if (File.Exists(name)){
                        if (RemoveCert(name) == true)
                        {
                            DebugPrint("RemoveCert({0}) => TRUE", name);
                        }
                        else
                        {
                            DebugPrint("RemoveCert({0}) => FALSE", name);
                        }
                    }
                    else
                    {
                        Console.WriteLine("ERROR : File {0} not found", name);
                    }
                }

            }

            
            Environment.Exit(0);
            



         }
    }
}
