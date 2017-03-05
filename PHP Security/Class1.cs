using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.IO;
using System.Diagnostics;
using System.Collections.Specialized;

namespace PHP_Game
{
	public class Game
	{

		private static Credentials cred {get; set;}
		private static Security sec {get; set;}

		const string apiUrl = "http://gimmeahit.x10host.com/Synth-Surv/unity-test.php";

		static Game() 
		{
			sec = new Security(667, "ikillnukes is cool");
			if (cred == null)
			{
				// Consultar a la página con la key principal para obtener los credenciales encriptados
				NameValueCollection query = new NameValueCollection();
				query.Add("action", "login");
				query.Add("ikill_key", "@uw716K8ÑV53JydCñ");
				string getData = HTTPTools.GetPostData(query);
				HttpWebRequest req = HttpWebRequest.Create(apiUrl+"?"+getData) as HttpWebRequest;
				string response = String.Empty;
				using (HttpWebResponse resp = req.GetResponse() as HttpWebResponse)
				{
					using (StreamReader sr = new StreamReader(resp.GetResponseStream()))
					{
						response = sr.ReadToEnd();
					}
				}
				string[] decrypt = sec.decrypt(response).Split(':');
				cred = new Credentials(decrypt[0], decrypt[1]);
			}
		}

		public static bool CheckForInternetConnection()
		{
			return System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable();
		}

		public static bool Login(string username, string password) {
			NameValueCollection query = new NameValueCollection();
			query.Add("action", "login");
			query.Add("username", username);
			query.Add("password", password);
			string postData = HTTPTools.GetPostData(query);
			HttpWebRequest req = HttpWebRequest.Create(apiUrl) as HttpWebRequest;
			HTTPTools.SetBasicAuthHeader(req, cred.username, cred.password);
			req.Method = "POST";
			req.ContentType = "application/x-www-form-urlencoded";
			byte[] bytes = Encoding.UTF8.GetBytes(postData);
			req.ContentLength = bytes.Length;
			string response = String.Empty;
			using (Stream requestStream = req.GetRequestStream())
			{
				requestStream.Write(bytes, 0, bytes.Length);
			}
			using (HttpWebResponse resp = req.GetResponse() as HttpWebResponse)
			{
				Encoding encoding = Encoding.GetEncoding(resp.CharacterSet);
				using (StreamReader sr = new StreamReader(resp.GetResponseStream(), encoding))
				{
					response = sr.ReadToEnd();
				}
			}
			return response.Contains("Te has logueado como");
		}
		
	}

	class HTTPTools 
	{

		public static string GetPostData(NameValueCollection n) {

			var parameters = new StringBuilder();

			for (int i = 0; i < n.AllKeys.Length; ++i)
			{
				parameters.AppendFormat("{0}={1}",
					n.GetKey(i),
					n[n.GetKey(i)]);
				if (i < n.AllKeys.Length - 1)
					parameters.AppendFormat("&");
			}

			return parameters.ToString();

		}

		public static void SetBasicAuthHeader(WebRequest req, String userName, String userPassword)
		{
			string authInfo = userName + ":" + userPassword;
			authInfo = Convert.ToBase64String(Encoding.Default.GetBytes(authInfo));
			req.Headers["Authorization"] = "Basic " + authInfo;
		}

	}

	public class Credentials 
	{
		public Credentials(string u, string p) 
		{
			username = u;
			password = p;
		}
		public string username;
		public string password;
		public override string ToString()
		{
			return username+":"+password;
		}
	}

	public class Security
	{
		public Security(int seed, string key) {
			this.seed = seed;
			this.key = key;
		}

		int seed = 0;
		string key = "";
		string patt = "abcdefghijklmnopqrstuvwxyz";

		public string encrypt(string str) {
	
			string encryptedString = "";
			List<string> arrayPattern = new List<string>();
			int length = str.Length;

			for(int i = 0; i < 10; i++) {
				arrayPattern.Add(randomize(patt, seed+i));
			}

			for(int i = 0; i < length; i++) {
				int index = ((int)str[i])/patt.Length;
				encryptedString += index+arrayPattern[index][(int)(str[i])%patt.Length];
			}

			return encryptedString;
		}

		public string decrypt(string str) {
	
			string decryptedString = "";
			List<string> arrayPattern = new List<string>();
			int length = str.Length;

			for(int i = 0; i < 10; i++) {
				arrayPattern.Add(randomize(patt, seed+i));
			}

			int index = 0;
	
			for (int i = 0; i < length; i++) {
				if((i % 2 == 0)) {
					index = int.Parse(str[i].ToString());
				} else {
					decryptedString += (char)(index*patt.Length+arrayPattern[index].IndexOf(str[i]));
				}
			}

			return decryptedString;
		}

		// generate random number
		int rand(int min = 0, int max = 9999999, int? s = null) {
			int temp_seed = ((s == null) ? seed : (int)s);
			int temp_key = ((String.IsNullOrEmpty(key)) ? new Random().Next() : ToInt(key));
			if (temp_seed == 0) seed = new Random().Next();
			temp_seed = (temp_seed * 493) % temp_key;
			return temp_seed % (max - min + 1) + min;
		}

		string randomize(string str, int? s = null) {
			string shuffled_str = "";
			string temp_str = str;
			int l = str.Length;
			for(int i = 0; i < l; i++) {
				int index = rand(0, temp_str.Length - 1, s);
				shuffled_str += temp_str[index];
				temp_str = removechar(temp_str, index);
			}
			return shuffled_str;
		}

		string removechar(string str, int index) {
			return str.Remove(index, 1);
		}

		int ToInt(string str) {
			if (String.IsNullOrEmpty(str)) return 0;
			int InternalSeed = 0;
			for(int x = 0; x < str.Length; x++) {
				if(!Char.IsDigit(str[x])) {
					InternalSeed += (int)(Convert.ToInt32(str[x])*Math.Pow(x, 3));
				} else {
					InternalSeed += (int)((int)(str[x])*Math.Pow(x, 3));
				}
			}
			return InternalSeed;
		}
	}

	public class EncodingTools 
	{

		public static string UTF8toASCII(string text)
		{
			System.Text.Encoding utf8 = System.Text.Encoding.UTF8;
			Byte[] encodedBytes = utf8.GetBytes(text);
			Byte[] convertedBytes =
					Encoding.Convert(Encoding.UTF8, Encoding.ASCII, encodedBytes);
			System.Text.Encoding ascii = System.Text.Encoding.ASCII;

			return ascii.GetString(convertedBytes);
		}

		public static string UnicodetoASCII(string text)
		{
			System.Text.Encoding unicode = System.Text.Encoding.Unicode;
			Byte[] encodedBytes = unicode.GetBytes(text);
			Byte[] convertedBytes =
					Encoding.Convert(Encoding.UTF8, Encoding.ASCII, encodedBytes);
			System.Text.Encoding ascii = System.Text.Encoding.ASCII;

			return ascii.GetString(convertedBytes);
		}

		// Function to detect the encoding for UTF-7, UTF-8/16/32 (bom, no bom, little
		// & big endian), and local default codepage, and potentially other codepages.
		// 'taster' = number of bytes to check of the file (to save processing). Higher
		// value is slower, but more reliable (especially UTF-8 with special characters
		// later on may appear to be ASCII initially). If taster = 0, then taster
		// becomes the length of the file (for maximum reliability). 'text' is simply
		// the string with the discovered encoding applied to the file.
		public static Encoding detectTextEncoding(byte[] b, out String text)
		{

			int taster = b.Length;

			//////////////// First check the low hanging fruit by checking if a
			//////////////// BOM/signature exists (sourced from http://www.unicode.org/faq/utf_bom.html#bom4)
			if (b.Length >= 4 && b[0] == 0x00 && b[1] == 0x00 && b[2] == 0xFE && b[3] == 0xFF) { text = Encoding.GetEncoding("utf-32BE").GetString(b, 4, b.Length - 4); return Encoding.GetEncoding("utf-32BE"); }  // UTF-32, big-endian 
			else if (b.Length >= 4 && b[0] == 0xFF && b[1] == 0xFE && b[2] == 0x00 && b[3] == 0x00) { text = Encoding.UTF32.GetString(b, 4, b.Length - 4); return Encoding.UTF32; }    // UTF-32, little-endian
			else if (b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF) { text = Encoding.BigEndianUnicode.GetString(b, 2, b.Length - 2); return Encoding.BigEndianUnicode; }     // UTF-16, big-endian
			else if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) { text = Encoding.Unicode.GetString(b, 2, b.Length - 2); return Encoding.Unicode; }              // UTF-16, little-endian
			else if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) { text = Encoding.UTF8.GetString(b, 3, b.Length - 3); return Encoding.UTF8; } // UTF-8
			else if (b.Length >= 3 && b[0] == 0x2b && b[1] == 0x2f && b[2] == 0x76) { text = Encoding.UTF7.GetString(b, 3, b.Length - 3); return Encoding.UTF7; } // UTF-7


			//////////// If the code reaches here, no BOM/signature was found, so now
			//////////// we need to 'taste' the file to see if can manually discover
			//////////// the encoding. A high taster value is desired for UTF-8
			//if (taster == 0 || taster > b.Length) taster = b.Length;    // Taster size can't be bigger than the filesize obviously.


			// Some text files are encoded in UTF8, but have no BOM/signature. Hence
			// the below manually checks for a UTF8 pattern. This code is based off
			// the top answer at: http://stackoverflow.com/questions/6555015/check-for-invalid-utf8
			// For our purposes, an unnecessarily strict (and terser/slower)
			// implementation is shown at: http://stackoverflow.com/questions/1031645/how-to-detect-utf-8-in-plain-c
			// For the below, false positives should be exceedingly rare (and would
			// be either slightly malformed UTF-8 (which would suit our purposes
			// anyway) or 8-bit extended ASCII/UTF-16/32 at a vanishingly long shot).
			int i = 0;
			bool utf8 = false;
			while (i < taster - 4)
			{
				if (b[i] <= 0x7F) { i += 1; continue; }     // If all characters are below 0x80, then it is valid UTF8, but UTF8 is not 'required' (and therefore the text is more desirable to be treated as the default codepage of the computer). Hence, there's no "utf8 = true;" code unlike the next three checks.
				if (b[i] >= 0xC2 && b[i] <= 0xDF && b[i + 1] >= 0x80 && b[i + 1] < 0xC0) { i += 2; utf8 = true; continue; }
				if (b[i] >= 0xE0 && b[i] <= 0xF0 && b[i + 1] >= 0x80 && b[i + 1] < 0xC0 && b[i + 2] >= 0x80 && b[i + 2] < 0xC0) { i += 3; utf8 = true; continue; }
				if (b[i] >= 0xF0 && b[i] <= 0xF4 && b[i + 1] >= 0x80 && b[i + 1] < 0xC0 && b[i + 2] >= 0x80 && b[i + 2] < 0xC0 && b[i + 3] >= 0x80 && b[i + 3] < 0xC0) { i += 4; utf8 = true; continue; }
				utf8 = false; break;
			}
			if (utf8 == true)
			{
				text = Encoding.UTF8.GetString(b);
				return Encoding.UTF8;
			}


			// The next check is a heuristic attempt to detect UTF-16 without a BOM.
			// We simply look for zeroes in odd or even byte places, and if a certain
			// threshold is reached, the code is 'probably' UF-16.          
			double threshold = 0.1; // proportion of chars step 2 which must be zeroed to be diagnosed as utf-16. 0.1 = 10%
			int count = 0;
			for (int n = 0; n < taster; n += 2) if (b[n] == 0) count++;
			if (((double)count) / taster > threshold) { text = Encoding.BigEndianUnicode.GetString(b); return Encoding.BigEndianUnicode; }
			count = 0;
			for (int n = 1; n < taster; n += 2) if (b[n] == 0) count++;
			if (((double)count) / taster > threshold) { text = Encoding.Unicode.GetString(b); return Encoding.Unicode; } // (little-endian)


			// Finally, a long shot - let's see if we can find "charset=xyz" or
			// "encoding=xyz" to identify the encoding:
			for (int n = 0; n < taster - 9; n++)
			{
				if (
					((b[n + 0] == 'c' || b[n + 0] == 'C') && (b[n + 1] == 'h' || b[n + 1] == 'H') && (b[n + 2] == 'a' || b[n + 2] == 'A') && (b[n + 3] == 'r' || b[n + 3] == 'R') && (b[n + 4] == 's' || b[n + 4] == 'S') && (b[n + 5] == 'e' || b[n + 5] == 'E') && (b[n + 6] == 't' || b[n + 6] == 'T') && (b[n + 7] == '=')) ||
					((b[n + 0] == 'e' || b[n + 0] == 'E') && (b[n + 1] == 'n' || b[n + 1] == 'N') && (b[n + 2] == 'c' || b[n + 2] == 'C') && (b[n + 3] == 'o' || b[n + 3] == 'O') && (b[n + 4] == 'd' || b[n + 4] == 'D') && (b[n + 5] == 'i' || b[n + 5] == 'I') && (b[n + 6] == 'n' || b[n + 6] == 'N') && (b[n + 7] == 'g' || b[n + 7] == 'G') && (b[n + 8] == '='))
					)
				{
					if (b[n + 0] == 'c' || b[n + 0] == 'C') n += 8; else n += 9;
					if (b[n] == '"' || b[n] == '\'') n++;
					int oldn = n;
					while (n < taster && (b[n] == '_' || b[n] == '-' || (b[n] >= '0' && b[n] <= '9') || (b[n] >= 'a' && b[n] <= 'z') || (b[n] >= 'A' && b[n] <= 'Z')))
					{ n++; }
					byte[] nb = new byte[n - oldn];
					Array.Copy(b, oldn, nb, 0, n - oldn);
					try
					{
						string internalEnc = Encoding.ASCII.GetString(nb);
						text = Encoding.GetEncoding(internalEnc).GetString(b);
						return Encoding.GetEncoding(internalEnc);
					}
					catch { break; }    // If C# doesn't recognize the name of the encoding, break.
				}
			}


			// If all else fails, the encoding is probably (though certainly not
			// definitely) the user's local codepage! One might present to the user a
			// list of alternative encodings as shown here: http://stackoverflow.com/questions/8509339/what-is-the-most-common-encoding-of-each-language
			// A full list can be found using Encoding.GetEncodings();
			text = Encoding.Default.GetString(b);
			return Encoding.Default;
		}

		public static byte[] GetBytes(string str)
		{
			byte[] bytes = new byte[str.Length * sizeof(char)];
			System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
			return bytes;
		}

		public static string GetString(byte[] bytes)
		{
			char[] chars = new char[bytes.Length / sizeof(char)];
			System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
			return new string(chars);
		}

	}

}
