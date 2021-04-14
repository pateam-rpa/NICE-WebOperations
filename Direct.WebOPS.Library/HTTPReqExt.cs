using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.IO;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Remoting.Messaging;

using log4net;
using Direct.Shared;
using Direct.Shared.Library;
using Direct.Interface;

namespace Direct.WebOps.Library
{
    [DirectDom("Http Request Extended", "Communication", false)]
    public class HttpRequest2 : DirectComponentBase
    {
        private static readonly ILog logArchitect = LogManager.GetLogger(Loggers.LibraryObjects);

        [DirectDom]
        public delegate void HTTPExceptionEventHandler(IDirectComponentBase sender, HTTPExceptionEventArgs2 e);

        [DirectDom("Exception 2")]
        public event HTTPExceptionEventHandler ExceptionEvent;

        #region Private Fields

        protected PropertyHolder<string> _Url = new PropertyHolder<string>("Url");
        protected PropertyHolder<string> _RequestMethod = new PropertyHolder<string>("RequestMethod");
        protected PropertyHolder<string> _ContentType = new PropertyHolder<string>("ContentType");
        protected PropertyHolder<string> _UserName = new PropertyHolder<string>("UserName");
        protected PropertyHolder<string> _Password = new PropertyHolder<string>("Password");
        protected PropertyHolder<string> _InboundEncoding = new PropertyHolder<string>("InboundEncoding");
        protected PropertyHolder<string> _OutgoingEncoding = new PropertyHolder<string>("OutgoingEncoding");
        protected PropertyHolder<string> _ProxyServer = new PropertyHolder<string>("ProxyServer");
        protected PropertyHolder<int> _ProxyPort = new PropertyHolder<int>("ProxyPort");
        protected PropertyHolder<bool> _WinAuth = new PropertyHolder<bool>("WinAuth");
        protected PropertyHolder<string> _UserAgent = new PropertyHolder<string>("UserAgent");
        protected PropertyHolder<string> _XmlRequest = new PropertyHolder<string>("XmlRequest");
        protected PropertyHolder<string> _XmlResponse = new PropertyHolder<string>("XmlResponse");
        protected PropertyHolder<int> _ResponseStatusCode = new PropertyHolder<int>("ResponseStatusCode");
        protected PropertyHolder<string> _ResponseStatusDescription = new PropertyHolder<string>("ResponseStatusDescription");
        protected PropertyHolder<int> _Timeout = new PropertyHolder<int>("Timeout");
        protected PropertyHolder<bool> _PreAuthenticate = new PropertyHolder<bool>("PreAuthenticate");
        protected PropertyHolder<bool> _AllowRedirect = new PropertyHolder<bool>("AllowRedirect");
        protected PropertyHolder<string> _Accept = new PropertyHolder<string>("Accept");
        protected PropertyHolder<string> _CertPath = new PropertyHolder<string>("Certificate Path");
        protected PropertyHolder<string> _CertPass = new PropertyHolder<string>("Certificate Password");
        protected PropertyHolder<string> _MediaType = new PropertyHolder<string>("MediaType");
        protected CollectionPropertyHolder<HTTPHeader> _RespHeaders = new CollectionPropertyHolder<HTTPHeader>("ResponseHeaders");
        private NameValueCollection _Headers;

        #endregion Private Fields

        #region Constructor(s)

        public HttpRequest2()
        {
            Initialize();
        }

        public HttpRequest2(IProject project)
            : base(project)
        {
            Initialize();
        }

        #endregion

        #region Operations

        [DirectDom("Download File")]
        [DirectDomMethod("Download {filepath}")]
        [MethodDescriptionAttribute("Download File from URL")]
        public bool downloadfile(string filepath)
        {
            using (var client = new WebClient())
            {
                //add headers
                int iCount = this._Headers.Count;
                string key;
                string keyvalue;
                for (int i = 0; i < iCount; i++)
                {
                    key = this._Headers.Keys[i];
                    keyvalue = this._Headers[i];
                    client.Headers.Add(key, keyvalue);
                }
                client.DownloadFile(this.Url, filepath);
            }
            return true;
        }


        [DirectDom("URL Encode String")]
        [DirectDomMethod("URL Encode {string}")]
        [MethodDescriptionAttribute("URL Encode a string")]
        public string urlencode(string text)
        {
            string result = WebUtility.UrlEncode(text);
            if (logArchitect.IsDebugEnabled)
                logArchitect.DebugFormat("HttpRequest.URLEncode - From {0}, To {1}", text, result);
            return result;
        }


        [DirectDom("URL Decode String")]
        [DirectDomMethod("URL Decode {string}")]
        [MethodDescriptionAttribute("URL Decode a string")]
        public string urldecode(string text)
        {
            string result = WebUtility.UrlDecode(text);
            if (logArchitect.IsDebugEnabled)
                logArchitect.DebugFormat("HttpRequest.URLDecode - From {0}, To {1}", text, result);
            return result;
        }


        [DirectDom("Add Header")]
        [DirectDomMethod("Add {Header} with {Value} to header of request")]
        [MethodDescriptionAttribute("Adds a header to the HTTP request")]
        public void AddHeader(string Header, string Value)
        {
            if (string.IsNullOrEmpty(Header) || string.IsNullOrEmpty(Value))
            {
                logArchitect.Error("HttpRequest.AddHeader - Invalid arguments");
                return;
            }

            _Headers.Add(Header, Value);
        }

        [DirectDom("Remove Header")]
        [DirectDomMethod("Remove {Header} from request header")]
        [MethodDescriptionAttribute("Removes a header from the HTTP request")]
        public void RemoveHeader(string Header)
        {
            if (string.IsNullOrEmpty(Header))
            {
                logArchitect.Error("HttpRequest.AddHeader - Invalid argument");
                return;
            }

            _Headers.Remove(Header);
        }

        private string getResponseBodyFromException(System.Net.WebException exception)
        {
            return new StreamReader(exception.Response.GetResponseStream()).ReadToEnd();
        }

        [DirectDom("Post Request")]
        [DirectDomMethod("Post request to a web server")]
        [MethodDescriptionAttribute("Posts a request to a Web Server")]
        public bool PostRequest()
        {
            try
            {
                if (logArchitect.IsInfoEnabled)
                    logArchitect.Info("HttpRequest.PostRequest - Start");

                if (logArchitect.IsDebugEnabled)
                    logArchitect.DebugFormat("HttpRequest.PostRequest - request {0}, url {1}, context {2}, type {3}", this.XmlRequest, this.Url, this.ContentType, this.RequestMethod);

                this.XmlResponse = InternalPostRequest();

                if (logArchitect.IsInfoEnabled)
                    logArchitect.InfoFormat("HttpRequest.PostRequest - Web Server response: {0}", this.XmlResponse);

                return true;
            }
            catch (System.Net.WebException ex)
            {
                string responseBody = getResponseBodyFromException(ex);
                logArchitect.ErrorFormat("HttpRequest.PostRequest - ERROR!!! WebException - {0}", ex.Message);
                logArchitect.ErrorFormat("HttpRequest.PostRequest - ERROR!!! WebException - Response Body - {0}", responseBody);
                if (ExceptionEvent != null)
                {
                    HttpStatusCode? status = (ex.Response as HttpWebResponse)?.StatusCode;
                    string message = string.Format("Post Request Asynchronous Error - {0} - {1}", status, ex.Message);
                    HTTPExceptionEventArgs2 arg = new HTTPExceptionEventArgs2(message, (int)status);
                    ExceptionEvent(this, arg);
                }
            }
            catch (System.Exception ex)
            {
                logArchitect.ErrorFormat("HttpRequest.PostRequest - ERROR!!! Exception - {0}", ex.Message);
                if (ExceptionEvent != null)
                {
                    string message = string.Format("Post Request Error - {0}", ex.Message);
                    HTTPExceptionEventArgs2 arg = new HTTPExceptionEventArgs2(message, 0);
                    ExceptionEvent(this, arg);
                }
            }

            return false;
        }

        [DirectDom("Post Request Asynchronously")]
        [DirectDomMethod("Post request to a web server asynchronously")]
        [MethodDescriptionAttribute("Posts a request to a Web Server asynchronously")]
        public void PostRequestAsynchronous()
        {
            if (logArchitect.IsInfoEnabled)
                logArchitect.Info("HttpRequest.PostRequestAsynchronous - Start");

            // Call to the 'InternalPostRequest' method asynchronously.
            PostRequestDelegate dlgt = new PostRequestDelegate(InternalPostRequest);
            dlgt.BeginInvoke(new AsyncCallback(Callback), null);
        }

        // This Callbak method is called when the InternalPostRequest method finishes its work.
        void Callback(IAsyncResult asyncResult)
        {
            try
            {
                PostRequestDelegate dlgt = (PostRequestDelegate)((AsyncResult)asyncResult).AsyncDelegate;
                string result = dlgt.EndInvoke(asyncResult);

                if (result == null)
                {
                    logArchitect.ErrorFormat("HttpRequest.Callback - response is null");
                    return;
                }

                // Invoke SetData on the logic thread.
                IDirectMessageQueue messageQueue = Project.MainFramework[PluginName.DirectMessageQueue] as IDirectMessageQueue;
                messageQueue.Post(new SetDataDelegate(SetData), result);

                if (logArchitect.IsInfoEnabled)
                    logArchitect.InfoFormat("HttpRequest.PostRequestAsynchronous - Web Server response: {0}", result);
            }
            catch (System.Net.WebException ex)
            {
                string responseBody = getResponseBodyFromException(ex);
                logArchitect.ErrorFormat("HttpRequest.PostRequestAsynchronous - ERROR!!! WebException - {0}", ex.Message);
                logArchitect.ErrorFormat("HttpRequest.PostRequest - ERROR!!! WebException - Response Body - {0}", responseBody);
                if (ExceptionEvent != null)
                {
                    HttpStatusCode? status = (ex.Response as HttpWebResponse)?.StatusCode;
                    string message = string.Format("Post Request Asynchronous Error - {0} - {1}", status, ex.Message);
                    HTTPExceptionEventArgs2 arg = new HTTPExceptionEventArgs2(message, (int)status);
                    ExceptionEvent(this, arg);
                   
                }
            }
            catch (System.Exception ex)
            {
                logArchitect.ErrorFormat("HttpRequest.PostRequestAsynchronous - ERROR!!! Exception - {0}", ex.Message);
                if (ExceptionEvent != null)
                {
                    string message = string.Format("Post Request Asynchronous Error - {0}", ex.Message);
                    HTTPExceptionEventArgs2 arg = new HTTPExceptionEventArgs2(message, 0);
                    ExceptionEvent(this, arg);
                }
            }
        }

        // This delegate is used for invoking the SetData through the Message Queue.
        delegate void SetDataDelegate(string value);
        // This delegate is used for asynchronous call of the InternalPostRequest method.
        delegate string PostRequestDelegate();

        // Set refreshed data.
        void SetData(string value)
        {
            this.XmlResponse = value;
        }


        string InternalPostRequest()
        {
            ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(CheckValidationResult);
            if (new Uri(this.Url).Scheme == Uri.UriSchemeHttps) { 
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            };

            if (this.OutgoingEncoding == string.Empty)
                this.OutgoingEncoding = "iso-8859-8";
            if (this.InboundEncoding == string.Empty)
                this.InboundEncoding = "iso-8859-8";

            if (this.RequestMethod == string.Empty)
            {
                logArchitect.Error("HttpRequest.PostRequest - Request method cannot be empty");
                throw new Exception("Request method cannot be empty");
            }

            Encoding OutEncoding = Encoding.GetEncoding(this.OutgoingEncoding);
            byte[] buffer = OutEncoding.GetBytes(this.XmlRequest);

            // Prepare web request...
            HttpWebRequest myRequest = (HttpWebRequest)WebRequest.Create(this.Url);
            myRequest.PreAuthenticate = this.PreAuthenticate;
            myRequest.AllowAutoRedirect = this.AllowRedirect;
            myRequest.Accept = this.Accept;
            myRequest.MediaType = this.MediaType;

            if (logArchitect.IsDebugEnabled)
                logArchitect.DebugFormat("HttpRequest - Checking if we have a certificate {0} and if the url is https {1}", new Uri(this.Url).Scheme.ToString(), this.CertPath);
            // Attach the client certificate if https and certPath specified.
            if (new Uri(this.Url).Scheme == Uri.UriSchemeHttps && this.CertPath != "")
            {
                if (logArchitect.IsDebugEnabled)
                    logArchitect.DebugFormat("HttpRequest - Adding certificate from {0}", this.CertPath);
                X509Certificate2Collection certificates = new X509Certificate2Collection();
                //certificates.Import(this.CertPath, this.CertPass, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                certificates.Import(this.CertPath, this.CertPass, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
                myRequest.ClientCertificates = certificates; 
            }

            if (WinAuth == true)
                myRequest.Credentials = CredentialCache.DefaultCredentials;

            myRequest.Method = this.RequestMethod;

            // Set the content type to a FORM
            myRequest.ContentType = this.ContentType;

            // Get length of content
            myRequest.ContentLength = buffer.Length;
            //add headers
            int iCount = this._Headers.Count;
            string key;
            string keyvalue;
            for (int i = 0; i < iCount; i++)
            {
                key = this._Headers.Keys[i];
                keyvalue = this._Headers[i];
                myRequest.Headers.Add(key, keyvalue);
            }

            //proxy
            if (this.ProxyServer.Length > 0)
            {
                myRequest.Proxy = new
                 WebProxy(this.ProxyServer, this.ProxyPort);
            }

            //myRequest.AllowAutoRedirect = false;

            // credentials
            if (this.UserName.Length > 0)
            {
                CredentialCache wrCache = new CredentialCache();
                wrCache.Add(new Uri(this.Url), "Basic", new NetworkCredential(this.UserName, this.Password));
                myRequest.Credentials = wrCache;
            }

            // user agent
            myRequest.UserAgent = this.UserAgent;

            // Timeout
            if (Timeout > 0)
                myRequest.Timeout = Timeout * 1000;

            if (myRequest.Method == "POST" || myRequest.Method == "PUT" || myRequest.Method == "PATCH")
            {
                // Get request stream
                Stream newStream = myRequest.GetRequestStream();

                // Send the data.
                newStream.Write(buffer, 0, buffer.Length);

                // Close stream
                newStream.Close();
            }

            // Assign the response object of 'HttpWebRequest' to a 'HttpWebResponse' variable.
            HttpWebResponse myHttpWebResponse = (HttpWebResponse)myRequest.GetResponse();

            this.ResponseHeaders.RemoveAll();
            for (int i = 0; i < myHttpWebResponse.Headers.Count; i++)
            {
                this.ResponseHeaders.Add(new HTTPHeader(myHttpWebResponse.Headers.Keys[i], myHttpWebResponse.Headers[i]));
            }
            this._ResponseStatusCode.TypedValue = (int)myHttpWebResponse.StatusCode;
            this._ResponseStatusDescription.TypedValue = myHttpWebResponse.StatusDescription.ToString();
            
            // Display the contents of the page to the console.
            Stream streamResponse = myHttpWebResponse.GetResponseStream();
            
            Encoding InEncoding = Encoding.GetEncoding(this.InboundEncoding);
            // Get stream object
            StreamReader streamRead = new StreamReader(streamResponse, InEncoding);

            Char[] readBuffer = new Char[256];

            // Read from buffer
            int count = streamRead.Read(readBuffer, 0, 256);

            StringBuilder sb = new StringBuilder();
            while (count > 0)
            {
                string s = new string(readBuffer, 0, count);
                // get string
                sb.Append(s);
                // Read from buffer
                count = streamRead.Read(readBuffer, 0, 256);
            }

            // Release the response object resources.
            streamRead.Close();
            streamResponse.Close();

            // Close response
            myHttpWebResponse.Close();

            return sb.ToString();
        }

        bool CheckValidationResult(object sender, X509Certificate certificate,
            X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private void Initialize()
        {
            _Headers = new NameValueCollection();
            ResponseHeaders = new DirectCollection<HTTPHeader>(this.Project);
            _Url.TypedValue = string.Empty;
            _RequestMethod.TypedValue = string.Empty;
            _InboundEncoding.TypedValue = string.Empty;
            _OutgoingEncoding.TypedValue = string.Empty;
            _ContentType.TypedValue = string.Empty;
            _UserName.TypedValue = string.Empty;
            _Password.TypedValue = string.Empty;
            _ProxyServer.TypedValue = string.Empty;
            _CertPass.TypedValue = string.Empty;
            _CertPath.TypedValue = string.Empty;
            _ProxyPort.TypedValue = 0;
            _WinAuth.TypedValue = false;
            _UserAgent.TypedValue = string.Empty;
            _XmlRequest.TypedValue = string.Empty;
            _XmlResponse.TypedValue = string.Empty;
            _ResponseStatusCode.TypedValue = 0;
            _ResponseStatusDescription.TypedValue = string.Empty;
            
        }

        #endregion

        #region Properties


        [DirectDom("Media Type")]
        public string MediaType
        {
            get { return _MediaType.TypedValue; }
            set { _MediaType.TypedValue = value; }
        }
        [DirectDom("Accept")]
        public string Accept
        {
            get { return _Accept.TypedValue; }
            set { _Accept.TypedValue = value; }
        }
        [DirectDom("Allow Redirect")]
        [DesignTimeInfo("Allow Redirect")]
        public bool AllowRedirect
        {
            get { return _AllowRedirect.TypedValue; }
            set { _AllowRedirect.TypedValue = value; }
        }

        [DirectDom("PreAuthenticate")]
        [DesignTimeInfo("PreAuthenticate")]
        public bool PreAuthenticate
        {
            get { return _PreAuthenticate.TypedValue; }
            set { _PreAuthenticate.TypedValue = value; }
        }

        [DirectDom("Url")]
        public string Url
        {
            get { return _Url.TypedValue; }
            set { _Url.TypedValue = value; }
        }

        [DirectDom("Request Method")]
        [DesignTimeInfo("Request Method")]
        public string RequestMethod
        {
            get { return _RequestMethod.TypedValue; }
            set { _RequestMethod.TypedValue = value; }
        }

        [DirectDom("Content Type")]
        [DesignTimeInfo("Content Type")]
        public string ContentType
        {
            get { return _ContentType.TypedValue; }
            set { _ContentType.TypedValue = value; }
        }

        [DirectDom("Certificate Path")]
        [DesignTimeInfo("Certificate Path")]
        public string CertPath
        {
            get { return _CertPath.TypedValue; }
            set { _CertPath.TypedValue = value; }
        }

        [DirectDom("Certificate Password")]
        [DesignTimeInfo("Certificate Password")]
        public string CertPass
        {
            get { return _CertPass.TypedValue; }
            set { _CertPass.TypedValue = value; }
        }

        [DirectDom("User Name")]
        [DesignTimeInfo("User Name")]
        public string UserName
        {
            get { return _UserName.TypedValue; }
            set { _UserName.TypedValue = value; }
        }

        [DirectDom("Password")]
        public string Password
        {
            get { return _Password.TypedValue; }
            set { _Password.TypedValue = value; }
        }

        [DirectDom("Windows Authentication")]
        [DesignTimeInfo("Windows Authentication")]
        public bool WinAuth
        {
            get { return _WinAuth.TypedValue; }
            set { _WinAuth.TypedValue = value; }
        }

        [DirectDom("Proxy Server")]
        [DesignTimeInfo("Proxy Server")]
        public string ProxyServer
        {
            get { return _ProxyServer.TypedValue; }
            set { _ProxyServer.TypedValue = value; }
        }

        [DirectDom("Proxy Port")]
        [DesignTimeInfo("Proxy Port")]
        public int ProxyPort
        {
            get { return _ProxyPort.TypedValue; }
            set { _ProxyPort.TypedValue = value; }
        }

        [DirectDom("User Agent")]
        [DesignTimeInfo("User Agent")]
        public string UserAgent
        {
            get { return _UserAgent.TypedValue; }
            set { _UserAgent.TypedValue = value; }
        }

        [DirectDom("Inbound Encoding")]
        [DesignTimeInfo("Inbound Encoding")]
        public string InboundEncoding
        {
            get { return _InboundEncoding.TypedValue; }
            set { _InboundEncoding.TypedValue = value; }
        }

        [DirectDom("Outgoing Encoding")]
        [DesignTimeInfo("Outgoing Encoding")]
        public string OutgoingEncoding
        {
            get { return _OutgoingEncoding.TypedValue; }
            set { _OutgoingEncoding.TypedValue = value; }
        }

        [DirectDom("Request")]
        [DesignTimeInfo("Request")]
        public string XmlRequest
        {
            get { return _XmlRequest.TypedValue; }
            set { _XmlRequest.TypedValue = value; }
        }

        [DirectDom("Response")]
        [DesignTimeInfo("Response")]
        public string XmlResponse
        {
            get { return _XmlResponse.TypedValue; }
            set { _XmlResponse.TypedValue = value; }
        }

        [DirectDom("Response StatusCode")]
        [DesignTimeInfo("Response StatusCode")]
        public int ResponseStatusCode
        {
            get { return _ResponseStatusCode.TypedValue; }
            set { _ResponseStatusCode.TypedValue = value; }
        }

        [DirectDom("Response StatusDescription")]
        [DesignTimeInfo("Response StatusDescription")]
        public string ResponseStatusDescription
        {
            get { return _ResponseStatusDescription.TypedValue; }
            set { _ResponseStatusDescription.TypedValue = value; }
        }

        [DirectDom("Timeout")]
        public int Timeout
        {
            get { return _Timeout.TypedValue; }
            set { _Timeout.TypedValue = value; }
        }

        [DirectDom("Response Headers")]
        public DirectCollection<HTTPHeader> ResponseHeaders
        {
            get { return this._RespHeaders.TypedValue; }
            set { this._RespHeaders.TypedValue = value; }
        }
        #endregion
    }
    #region HTTPExceptionEventArgs

    [DirectDom]
    [DirectSealed]
    public class HTTPExceptionEventArgs2 : DirectEventArgs
    {
        string message = string.Empty;

        int status = 0;

        public HTTPExceptionEventArgs2(string message, int status)
        {
            this.status = status;
            this.message = message;
        }

        [DirectDom("Message")]
        public string Message
        {
            get { return message; }
        }

        [DirectDom("Status")]
        public int Status
        {
            get { return status; }
        }

    }
    #endregion

    #region helperTypes
    [DirectDom("Header", "Http Request Extended", false)]
    public class HTTPHeader : DirectComponentBase
    {
        protected PropertyHolder<string> _Name = new PropertyHolder<string>("Name");
        protected PropertyHolder<string> _Value = new PropertyHolder<string>("Value");

        public HTTPHeader()
        {

        }

        public HTTPHeader(string name, string value)
        {
            this.Name = name;
            this.Value = value;
        }
        public HTTPHeader(IProject project)
        : base(project)
        {

        }


        [DirectDom("Name")]
        public string Name
        {
            get { return _Name.TypedValue; }
            set { this._Name.TypedValue = value; }
        }


        [DirectDom("Value")]
        public string Value
        {
            get { return _Value.TypedValue; }
            set { this._Value.TypedValue = value; }
        }



    }
    #endregion helperTypes

}