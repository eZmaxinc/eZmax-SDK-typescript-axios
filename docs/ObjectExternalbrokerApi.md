# ObjectExternalbrokerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**externalbrokerBatchDownloadV1**](#externalbrokerbatchdownloadv1) | **POST** /1/object/externalbroker/{pkiExternalbrokerID}/batchDownload | Download multiples attachments from an Externalbroker|
|[**externalbrokerGetAttachmentsV1**](#externalbrokergetattachmentsv1) | **GET** /1/object/externalbroker/{pkiExternalbrokerID}/getAttachments | Retrieve Externalbroker\&#39;s attachments|
|[**externalbrokerImportIntoEDMV1**](#externalbrokerimportintoedmv1) | **POST** /1/object/externalbroker/{pkiExternalbrokerID}/importIntoEDM | Import attachments into the Externalbroker|

# **externalbrokerBatchDownloadV1**
> File externalbrokerBatchDownloadV1(externalbrokerBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectExternalbrokerApi,
    Configuration,
    ExternalbrokerBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectExternalbrokerApi(configuration);

let pkiExternalbrokerID: number; // (default to undefined)
let externalbrokerBatchDownloadV1Request: ExternalbrokerBatchDownloadV1Request; //

const { status, data } = await apiInstance.externalbrokerBatchDownloadV1(
    pkiExternalbrokerID,
    externalbrokerBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **externalbrokerBatchDownloadV1Request** | **ExternalbrokerBatchDownloadV1Request**|  | |
| **pkiExternalbrokerID** | [**number**] |  | defaults to undefined|


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

# **externalbrokerGetAttachmentsV1**
> ExternalbrokerGetAttachmentsV1Response externalbrokerGetAttachmentsV1()


### Example

```typescript
import {
    ObjectExternalbrokerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectExternalbrokerApi(configuration);

let pkiExternalbrokerID: number; // (default to undefined)

const { status, data } = await apiInstance.externalbrokerGetAttachmentsV1(
    pkiExternalbrokerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiExternalbrokerID** | [**number**] |  | defaults to undefined|


### Return type

**ExternalbrokerGetAttachmentsV1Response**

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

# **externalbrokerImportIntoEDMV1**
> ExternalbrokerImportIntoEDMV1Response externalbrokerImportIntoEDMV1(externalbrokerImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectExternalbrokerApi,
    Configuration,
    ExternalbrokerImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectExternalbrokerApi(configuration);

let pkiExternalbrokerID: number; // (default to undefined)
let externalbrokerImportIntoEDMV1Request: ExternalbrokerImportIntoEDMV1Request; //

const { status, data } = await apiInstance.externalbrokerImportIntoEDMV1(
    pkiExternalbrokerID,
    externalbrokerImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **externalbrokerImportIntoEDMV1Request** | **ExternalbrokerImportIntoEDMV1Request**|  | |
| **pkiExternalbrokerID** | [**number**] |  | defaults to undefined|


### Return type

**ExternalbrokerImportIntoEDMV1Response**

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

