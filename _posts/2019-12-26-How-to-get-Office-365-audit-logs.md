---
layout: post
title: How to get Office 365 audit logs
subtitle: In two ways
comments: true
tags: ["logs","office 365","azure"]

# layout: post
# title: How to get Office 365 audit logs
# date: 2019-12-26 20:26
# category: Azure
# author: Jakub Dropia
# tags: ["logs","office 365","azure"]
---
Office 365 has option to [turn on](https://docs.microsoft.com/en-us/microsoft-365/compliance/turn-audit-log-search-on-or-off) unified audit logs.
Whenever users are using products like Azure, Exchange Online, Sway, Yammer and other, after turning on, they will start leaving footprints. 
This footprints are gathered in form of logs, which you can access in multiple ways. This solutions differ in terms of limitations and access methods.
I had opportunity to take closer look on those and would like to share some thoughts and code snippets :)

# Case

I had simple requirements:  
- Dump all Office 365 audit logs to Blob Storage for all users of given Active Directory User Group (relatively small group of Users (50 - 1000) comparing to whole tenant (50 000)) 
- Dump can be delayed, it doesn't have to be in real-time
- Nice to have one json file per day
- Nice to have authorization more advanced than Basic Auth

# Study

## Access methods

There are two main methods of getting logs:

1) [Security & Compliance Center](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance)
   - Access via Web UI
   - Access via Exchange Online Powershell cmdlet **Search-UnifiedAuditLog**
   - Access via [https://outlook.office365.com/psws/service.svc/UnifiedAuditLog](https://outlook.office365.com/psws/service.svc/UnifiedAuditLog)
  
2) [Office 365 Management Activity API](https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference)

{: .box-note}
**Note:** You have to be assigned the View-Only Audit Logs or Audit Logs role in Exchange Online to search the Office 365 audit log.

{: .box-note}
**Note:** You can find what logs are gathered [here](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance#before-you-begin)

## Characteristics of the methods

Both of them can return the same set of logs from different sources and products of Office 365. However they significantly differ:

1) Security & Compliance Center 
   - You can search using Web UI
   - Using [https://outlook.office365.com/psws/service.svc/UnifiedAuditLog](https://outlook.office365.com/psws/service.svc/UnifiedAuditLog)
     - you can filter by user principals
     - you can pass date range wider than 24h
     - some more useful filters
     - one call can return max 400 elements
     - is slow
     - only Basic Auth
     - paging is tricky, but in the end - simple (see more in later paragraphs)

{: .box-note}
**Note:** How slow it is?  
Getting one page of 400 elements takes up to 10 seconds.

2) Office 365 Management Activity API
   - No Web UI
   - Recommended for getting logs programmatically 
   - Logs are delivered as blobs
   - Fast
   - Advanced authorization (Azure AD and the OAuth2)
   - Simple paging by NextPageUri
   - Webhooks available ([but not recommended](https://docs.microsoft.com/en-us/office/office-365-management-api/troubleshooting-the-office-365-management-activity-api#using-webhooks))
   - You must subscribe first for specific contentType
   - Using pull method, you can ask for blobs only up to 24h range. 
   - Filtering only by contentType (you are getting list of all blobs for given period for given contentType)

## Conclusions

In terms of fulfilling our requirements, Office 365 Management API has one big disadvantage: **no user filtering**. This means, when getting logs, we need to download all of them, filter out, and save in separate storage only for given users. **This is not acceptable**, as our tenant is very big and we don't want to pre-process all this logs of 50 000 users.
This leaving us with UnifiedAuditLog service, which has some drawbacks to live with:
   - slow access
   - basic auth  

and resolve:  
   - tricky pagination

# Implementation

We have the winner. Let's try use it :)

## Plan
- Create HttpTrigger POST Azure Function for getting logs and store them in blobs grouped by date
  - Implement this as pass-through - support all query parameters as original one, providing only own values for pagination parameters (doc [here](https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance-audit/search-unifiedauditlog?view=exchange-ps))
- Create Logic App, to schedule execution of Azure Function (because TimeTrigger doesn't have any retry and failure policies). It will also get users of given User Group. (i am skipping this part in a post)

## Code

Full function under github [repo](https://github.com/darthkurak/office365auditlogs): 

### Basic

- Function supports all query parameters which UnifiedAuditLog [does](https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance-audit/search-unifiedauditlog?view=exchange-ps), expect: `SessionCommand`, `SessionId` and `ResultSize` which are provided by Function itself. 

- Additionally, you can pass `container` parameter with string value, to tell which container it should write. By default it will be `auditlogs`

- All results will be grouped by log creation date and appended to corresponding blob.

- If container doesn't exist - it will be created
  
- If blob doesn't exist - it will be created

- Function expects two settings: 
  - `Office365Credentials` in `userEmail:password` - it should be principal email of user who has access to unified audit logs
  - `AuditLogsStorage` - connection string to storage where audit logs should be written

### Pagination

Function is fairly simple. 
It uses https://outlook.office365.com/psws/service.svc/UnifiedAuditLog endpoint to get audit logs with passed parameters. 

Tricky part is pagination.
Despite UnifiedAuditLog [documentation](https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance-audit/search-unifiedauditlog?view=exchange-ps), which states that `ResultSize` can be up to 5000, API always return maximum **400 elements**. What is more, if `ResultSize` is bigger than 400 it will return following extra property in body json:

 ```"odata.nextLink": "../../psws/service.svc/UnifiedAuditLog?$skiptoken=400"```

This is very misleading. It suggest that API support skiptoken, and we should use it to paginate results and get more of our `ResultSize` list. Actually, putting this parameter into query do completely nothing. We will always get first 400 elements, no matter what value we put in skiptoken. 

Luckily, this HTTP endpoint supports all functionality and query parameters which are mentioned in `UnifiedAuditLog` documentation. Reading through it, reveal `SessionId` and `SessionCommand` parameters. Putting unique value (i am suggesting Guid) in `SessionId` and setting `SessionCommand` to 
`ReturnNextPreviewPage` allow us easily paginate our results just by simply **resend our requests**. Each time we should get next page of `ResultSize` size, however restricted to 400 elements. What is more - some items will be missed if set `ResultSize` **is bigger** than 400. (probably because powershell return ResultSize page, and items are restricted by api to 400, and then in next call, we getting next ResultSize page, which don't have this items cut by api)  
That is why, to work this properly, **ResultSize should be less or equal 400.** 

To summary, a proper request supporting pagination would look like:

`https://outlook.office365.com/psws/service.svc/UnifiedAuditLog?ResultSize=400&SessionId=810712e9-ad86-4c95-a8fe-60de57d7f4ef&SessionCommand=ReturnNextPreviewPage`

If you want, you can set `ResultSize` to less.

Function use above to paginate results:

```csharp
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AzFunction
{
    public static class WriteLogsToBlob
    {
        private static Lazy<HttpClient> HttpClient = new Lazy<HttpClient>(() =>
        {
            var httpClient = new HttpClient();

            var office365serviceCredentials = System.Environment.GetEnvironmentVariable("Office365Credentials", EnvironmentVariableTarget.Process);
            var byteArray = Encoding.ASCII.GetBytes(office365serviceCredentials);
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return httpClient;
        });

        private static Lazy<BlobManager> BlobManager = new Lazy<BlobManager>(() =>
        {
            var connectionString = System.Environment.GetEnvironmentVariable("AuditLogsStorage", EnvironmentVariableTarget.Process);
            return new BlobManager(new BlobProvider(connectionString));
        });

        [FunctionName("WriteLogsToBlob")]
        public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req, ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var queryItems = req.Query.SelectMany(x => x.Value, (col, value) => new KeyValuePair<string, string>(col.Key.ToLowerInvariant(), value)).ToList();

            var container = GetContainerName(queryItems);

            RemoveSelfHandledParameters(queryItems);

            log.LogInformation($"C# Http trigger function executed at: {DateTime.Now}");

            PrintQueryParameters(log, queryItems);

            AddPaginationParameters(queryItems);

            var uri = BuildUri(queryItems);

            return await GetLogsAndWriteToBlobs(log, container, uri);
        }

        private static string GetContainerName(List<KeyValuePair<string, string>> queryItems)
        {
            var container = "auditlogs";

            if (queryItems.Any(p => p.Key == "container"))
            {
                var val = queryItems.First(p => p.Key == "container").Value;

                if (!string.IsNullOrWhiteSpace(val))
                {
                    container = val;
                }
            }

            return container;
        }

        private static void RemoveSelfHandledParameters(List<KeyValuePair<string, string>> queryItems)
        {
            queryItems.RemoveAll(p => p.Key == "container" || p.Key == "sessioncommand" || p.Key == "sessionid" || p.Key == "resultsize");
        }

        private static void PrintQueryParameters(ILogger log, List<KeyValuePair<string, string>> queryItems)
        {
            foreach (var queryItem in queryItems)
            {
                log.LogInformation($"{queryItem.Key}: {queryItem.Value}");
            }
        }

        private static void AddPaginationParameters(List<KeyValuePair<string, string>> queryItems)
        {
            //this is unique session used for paging mechanism in Audit Log Api
            var sessionId = Guid.NewGuid();

            queryItems.Add(new KeyValuePair<string, string>("ResultSize", "300"));
            queryItems.Add(new KeyValuePair<string, string>("SessionId", sessionId.ToString()));
            queryItems.Add(new KeyValuePair<string, string>("SessionCommand", "ReturnNextPreviewPage"));
        }

        private static Uri BuildUri(List<KeyValuePair<string, string>> queryItems)
        {
            var queryBuilder = new QueryBuilder(queryItems);

            string url = $"https://outlook.office365.com/psws/service.svc/UnifiedAuditLog";

            var uriBuilder = new UriBuilder(url);

            uriBuilder.Query = queryBuilder.ToQueryString().Value;

            var uri = uriBuilder.Uri;

            return uri;
        }

        private static async Task<ActionResult> GetLogsAndWriteToBlobs(ILogger log, string container, Uri uri)
        {

            bool noMoreResults = false;

            //get auditLogs from Audit Log Api, loop until there is no more result, same sessionId is used to page API
            int sum = 0;
            do
            {
                var result = await HttpClient.Value.GetAsync(uri);

                if (!result.IsSuccessStatusCode)
                {
                    var response = await result.Content.ReadAsStringAsync();
                    var objectResult = new ObjectResult("Calling UnifiedAuditLog Api failed: " + response) { StatusCode = (int)result.StatusCode };
                    return objectResult;
                }

                var auditLog = await result.Content.ReadAsStringAsync();

                JObject auditLogObject = JObject.Parse(auditLog);
                var list = (auditLogObject["value"] as JArray);
                if (list?.Count > 0)
                {
                    log.LogInformation($"Writing {list.Count} dataLogs points");
                    sum += list.Count;
                    //Group logs by Date
                    var groups = list.GroupBy(p => GetKey(p));
                    foreach (var group in groups)
                    {
                        //Append them to blob, we selecting AuditData (actual logs)
                        await BlobManager.Value.AppendAsync(container, group.Key, Encoding.UTF8.GetBytes(string.Join("\n", group.Select(p => p["AuditData"])) + "\n"), log);
                    }
                }
                else
                {
                    noMoreResults = true;
                }
            }
            while (!noMoreResults);

            log.LogInformation($"Writing finished! {sum} dataLogs points was written.");

            return (ActionResult)new OkObjectResult($"Logs written {sum}");
        }

        private static string GetKey(JToken jToken)
        {
            var dateTime = jToken["CreationDate"].ToObject<DateTime>();
            return "auditlogs-" + dateTime.Year + "-" + dateTime.Month + "-" + dateTime.Day + ".json";
        }
    }
}
```








