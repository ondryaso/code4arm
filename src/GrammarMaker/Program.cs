using System.Text;
using System.Text.RegularExpressions;

namespace GrammarMaker;

public class Program
{
    public const string IndexFile =
        @"C:\Users\ondry\AppData\Roaming\Code\User\globalStorage\ondryaso.code4arm\docs\ISA_AArch32_xml_A_profile-2022-03\xhtml\index.html";

    public const string FpIndexFile =
        @"C:\Users\ondry\AppData\Roaming\Code\User\globalStorage\ondryaso.code4arm\docs\ISA_AArch32_xml_A_profile-2022-03\xhtml\fpsimdindex.html";

    public static async Task Main(string[] args)
    {
        await InstructionList.MakeInstructionList();
    }
}