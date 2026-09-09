# ObjectOfficetaxreportApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**officetaxreportBatchDownloadV1**](#officetaxreportbatchdownloadv1) | **POST** /1/object/officetaxreport/{pkiOfficetaxreportID}/batchDownload | Download multiples attachments from an Officetaxreport|
|[**officetaxreportGetAttachmentsV1**](#officetaxreportgetattachmentsv1) | **GET** /1/object/officetaxreport/{pkiOfficetaxreportID}/getAttachments | Retrieve Officetaxreport\&#39;s attachments|
|[**officetaxreportImportIntoEDMV1**](#officetaxreportimportintoedmv1) | **POST** /1/object/officetaxreport/{pkiOfficetaxreportID}/importIntoEDM | Import attachments into the Officetaxreport|

# **officetaxreportBatchDownloadV1**
> File officetaxreportBatchDownloadV1(officetaxreportBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration,
    OfficetaxreportBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let pkiOfficetaxreportID: number; // (default to undefined)
let officetaxreportBatchDownloadV1Request: OfficetaxreportBatchDownloadV1Request; //

const { status, data } = await apiInstance.officetaxreportBatchDownloadV1(
    pkiOfficetaxreportID,
    officetaxreportBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **officetaxreportBatchDownloadV1Request** | **OfficetaxreportBatchDownloadV1Request**|  | |
| **pkiOfficetaxreportID** | [**number**] |  | defaults to undefined|


### Return type

**File**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/zip, text/xml, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **officetaxreportGetAttachmentsV1**
> OfficetaxreportGetAttachmentsV1Response officetaxreportGetAttachmentsV1()


### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let pkiOfficetaxreportID: number; // (default to undefined)

const { status, data } = await apiInstance.officetaxreportGetAttachmentsV1(
    pkiOfficetaxreportID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOfficetaxreportID** | [**number**] |  | defaults to undefined|


### Return type

**OfficetaxreportGetAttachmentsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **officetaxreportImportIntoEDMV1**
> OfficetaxreportImportIntoEDMV1Response officetaxreportImportIntoEDMV1(officetaxreportImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration,
    OfficetaxreportImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let pkiOfficetaxreportID: number; // (default to undefined)
let officetaxreportImportIntoEDMV1Request: OfficetaxreportImportIntoEDMV1Request; //

const { status, data } = await apiInstance.officetaxreportImportIntoEDMV1(
    pkiOfficetaxreportID,
    officetaxreportImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **officetaxreportImportIntoEDMV1Request** | **OfficetaxreportImportIntoEDMV1Request**|  | |
| **pkiOfficetaxreportID** | [**number**] |  | defaults to undefined|


### Return type

**OfficetaxreportImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

