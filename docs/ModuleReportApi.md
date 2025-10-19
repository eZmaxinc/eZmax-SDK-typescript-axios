# ModuleReportApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**reportGetReportFromCacheV1**](#reportgetreportfromcachev1) | **GET** /1/module/report/getReportFromCache/{sReportgroupCacheID} | Retrieve report from cache|

# **reportGetReportFromCacheV1**
> CommonGetReportV1Response reportGetReportFromCacheV1()

Retrieve a report that was previously generated and cached

### Example

```typescript
import {
    ModuleReportApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ModuleReportApi(configuration);

let sReportgroupCacheID: string; // (default to undefined)

const { status, data } = await apiInstance.reportGetReportFromCacheV1(
    sReportgroupCacheID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sReportgroupCacheID** | [**string**] |  | defaults to undefined|


### Return type

**CommonGetReportV1Response**

### Authorization

[Authorization](../README.md#Authorization), [Presigned](../README.md#Presigned)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/pdf, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, application/zip, text/html


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

