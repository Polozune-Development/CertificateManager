using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Data;
using System.Data.Common;
using System.Data.SqlTypes;
using Microsoft.Data.Sql;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.DataClassification;
using Microsoft.Data.SqlClient.Diagnostics;
using Microsoft.Data.SqlClient.Internal;
using Microsoft.Data.SqlClient.Server;
using Microsoft.Data.SqlTypes;
using System.Dynamic;
using System.Formats;
using System.Formats.Asn1;
using System.Formats.Tar;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.IO.Enumeration;
using System.IO.IsolatedStorage;
using System.IO.MemoryMappedFiles;
using System.IO.Pipelines;
using System.IO.Pipes;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Cache;
using System.Net.NetworkInformation;
using System.Net.Quic;
using System.Net.Security;
using System.Net.ServerSentEvents;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Loader;
using System.Runtime.Remoting;
using System.Runtime.Serialization;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Schema;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using System.Threading.Tasks.Sources;
using Microsoft.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Binder;
using Microsoft.Extensions.Configuration.CommandLine;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Hosting.Systemd;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Http.Diagnostics;
using Microsoft.Extensions.Http.Latency;
using Microsoft.Extensions.Http.Logging;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Configuration;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Logging.Debug;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Logging.EventSource;
using Microsoft.Extensions.Logging.TraceSource;
using Microsoft.Extensions.AmbientMetadata;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Caching;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.VectorData;
using Microsoft.Extensions.VectorData.ProviderServices;
using Microsoft.Extensions.Internal;
using Microsoft.Agents;
using Microsoft.Agents.AI;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Agents;
using Microsoft.SemanticKernel.ChatCompletion;
using Microsoft.SemanticKernel.Data;
using Microsoft.SemanticKernel.Embeddings;
using Microsoft.SemanticKernel.Functions;
using Microsoft.SemanticKernel.Memory;
using Microsoft.SemanticKernel.Services;
using Microsoft.SemanticKernel.Text;
using Microsoft.SemanticKernel.TextGeneration;
using Microsoft.SemanticKernel.TextToAudio;
using Microsoft.SemanticKernel.TextToImage;
using Org.BouncyCastle;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.Field;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Pqc;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace CertificateManager
{
    internal class CertHelper
    {
        public sealed class Certificate
        {
            public required string FriendlyName
            {
                get;
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length > 128)
                    {
                        throw new ArgumentException("FriendlyName must be a string with a maximum length of 128 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string CommonName 
            { 
                get; 
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length > 360)
                    {
                        throw new ArgumentException("CommonName must be a string with a maximum length of 360 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string SerialNumber
            {
                get;
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length != 24)
                    {
                        throw new ArgumentException("SerialNumber should be a 24-character hexadecimal string.", nameof(value));
                    }
                    field = value.ToUpperInvariant();
                }
            }
            public required DateTime NotBefore { get; set; }
            public required DateTime NotAfter { get; set; }
            public required string Issuer
            {
                get;
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length > 64)
                    {
                        throw new ArgumentException("Issuer must be a string with a maximum length of 64 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string PublicKey { get; set; }
            public string? PrivateKey { get; set; }
            public required string KeyAlgorithm
            {
                get;
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);

                    if (value.Length > 12)
                    {
                        throw new ArgumentException("KeyAlgorithm must be a string with a maximum length of 12 characters.", nameof(value));
                    }

                    field = value;
                }
            }
            public required string SignatureAlgorithm
            {
                get;
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);

                    if (value.Length > 12)
                    {
                        throw new ArgumentException("SignatureAlgorithm must be a string with a maximum length of 12 characters.", nameof(value));
                    }

                    field = value;
                }
            }
            public required string SignatureHashAlgorithm 
            { 
                get; 
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length > 24)
                    {
                        throw new ArgumentException("SignatureHashAlgorithm must be a string with a maximum length of 24 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string Subject { get; set; }
            public required string KeyUsage { get; set; }
            public string? EnhancedKeyUsage { get; set; }
            public required string BasicConstraints { get; set; }
            public string? CertificateVersion
            {
                get;
                set
                {
                    if (value.Length > 3)
                    {
                        throw new ArgumentException("CertificateVersion must be a string with a maximum length of 3 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string Thumbprint { 
                get;
                set 
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);

                    if (value.Length != 40)
                    {
                        throw new ArgumentException("Thumbprint must be a 40-character hexadecimal string.", nameof(value));
                    }

                    field = value.ToUpperInvariant();
                } 
            }
        }

        public sealed class RawCertificate
        {
            public required string FriendlyName 
            { 
                get; 
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length > 128)
                    {
                        throw new ArgumentException("FriendlyName must be a string with a maximum length of 128 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string Issuer 
            { 
                get; 
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length > 64)
                    {
                        throw new ArgumentException("Issuer must be a string with a maximum length of 64 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string SerialNumber 
            { 
                get; 
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length != 24)
                    {
                        throw new ArgumentException("SerialNumber should be a 24-character hexadecimal string.", nameof(value));
                    }
                    field = value.ToUpperInvariant();
                }
            }
            public required string CertificatePem { get; set; }
            public string? CertificatePassword { get; set; }
            public required string CertificateAlgorithm
            { get;
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);
                    if (value.Length > 12)
                    {
                        throw new ArgumentException("CertificateAlgorithm must be a string with a maximum length of 12 characters.", nameof(value));
                    }
                    field = value;
                }
            }
            public required string PublicKey { get; set; }
            public string? PrivateKey { get; set; }
            public required string KeyAlgorithm 
            { 
                get;
                set 
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);

                    if (value.Length > 12)
                    {
                        throw new ArgumentException("KeyAlgorithm must be a string with a maximum length of 12 characters.", nameof(value));
                    }

                    field = value;
                } 
            }
            public required string Thumbprint
            {
                get;
                set
                {
                    ArgumentNullException.ThrowIfNullOrEmpty(value);

                    if (value.Length != 40)
                    {
                        throw new ArgumentException("Thumbprint must be a 40-character hexadecimal string.", nameof(value));
                    }

                    field = value.ToUpperInvariant();
                }
            }
        }
    }
}
