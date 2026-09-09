# ObjectLeadApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**leadBatchDownloadV1**](#leadbatchdownloadv1) | **POST** /1/object/lead/{pkiLeadID}/batchDownload | Download multiples attachments from a Lead|
|[**leadGetAttachmentsV1**](#leadgetattachmentsv1) | **GET** /1/object/lead/{pkiLeadID}/getAttachments | Retrieve Lead\&#39;s attachments|
|[**leadGetListV1**](#leadgetlistv1) | **GET** /1/object/lead/getList | Retrieve Lead list|
|[**leadImportIntoEDMV1**](#leadimportintoedmv1) | **POST** /1/object/lead/{pkiLeadID}/importIntoEDM | Import attachments into the Lead|

# **leadBatchDownloadV1**
> File leadBatchDownloadV1(leadBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectLeadApi,
    Configuration,
    LeadBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectLeadApi(configuration);

let pkiLeadID: number; // (default to undefined)
let leadBatchDownloadV1Request: LeadBatchDownloadV1Request; //

const { status, data } = await apiInstance.leadBatchDownloadV1(
    pkiLeadID,
    leadBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **leadBatchDownloadV1Request** | **LeadBatchDownloadV1Request**|  | |
| **pkiLeadID** | [**number**] |  | defaults to undefined|


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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **leadGetAttachmentsV1**
> LeadGetAttachmentsV1Response leadGetAttachmentsV1()


### Example

```typescript
import {
    ObjectLeadApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectLeadApi(configuration);

let pkiLeadID: number; // (default to undefined)

const { status, data } = await apiInstance.leadGetAttachmentsV1(
    pkiLeadID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiLeadID** | [**number**] |  | defaults to undefined|


### Return type

**LeadGetAttachmentsV1Response**

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

# **leadGetListV1**
> LeadGetListV1Response leadGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eLeadStatus | New<br>Dispatching<br>Assigned<br>Lost<br>Won |

### Example

```typescript
import {
    ObjectLeadApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectLeadApi(configuration);

let eOrderBy: 'pkiLeadID_ASC' | 'pkiLeadID_DESC' | 'fkiLeadsourceID_ASC' | 'fkiLeadsourceID_DESC' | 'sLeadsourceNameX_ASC' | 'sLeadsourceNameX_DESC' | 'eLeadStatus_ASC' | 'eLeadStatus_DESC' | 'dtLeadExpiration_ASC' | 'dtLeadExpiration_DESC' | 'bLeadIsactive_ASC' | 'bLeadIsactive_DESC' | 'sLeadCode_ASC' | 'sLeadCode_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.leadGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiLeadID_ASC&#39; | &#39;pkiLeadID_DESC&#39; | &#39;fkiLeadsourceID_ASC&#39; | &#39;fkiLeadsourceID_DESC&#39; | &#39;sLeadsourceNameX_ASC&#39; | &#39;sLeadsourceNameX_DESC&#39; | &#39;eLeadStatus_ASC&#39; | &#39;eLeadStatus_DESC&#39; | &#39;dtLeadExpiration_ASC&#39; | &#39;dtLeadExpiration_DESC&#39; | &#39;bLeadIsactive_ASC&#39; | &#39;bLeadIsactive_DESC&#39; | &#39;sLeadCode_ASC&#39; | &#39;sLeadCode_DESC&#39;**]**Array<&#39;pkiLeadID_ASC&#39; &#124; &#39;pkiLeadID_DESC&#39; &#124; &#39;fkiLeadsourceID_ASC&#39; &#124; &#39;fkiLeadsourceID_DESC&#39; &#124; &#39;sLeadsourceNameX_ASC&#39; &#124; &#39;sLeadsourceNameX_DESC&#39; &#124; &#39;eLeadStatus_ASC&#39; &#124; &#39;eLeadStatus_DESC&#39; &#124; &#39;dtLeadExpiration_ASC&#39; &#124; &#39;dtLeadExpiration_DESC&#39; &#124; &#39;bLeadIsactive_ASC&#39; &#124; &#39;bLeadIsactive_DESC&#39; &#124; &#39;sLeadCode_ASC&#39; &#124; &#39;sLeadCode_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**LeadGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **leadImportIntoEDMV1**
> LeadImportIntoEDMV1Response leadImportIntoEDMV1(leadImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectLeadApi,
    Configuration,
    LeadImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectLeadApi(configuration);

let pkiLeadID: number; // (default to undefined)
let leadImportIntoEDMV1Request: LeadImportIntoEDMV1Request; //

const { status, data } = await apiInstance.leadImportIntoEDMV1(
    pkiLeadID,
    leadImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **leadImportIntoEDMV1Request** | **LeadImportIntoEDMV1Request**|  | |
| **pkiLeadID** | [**number**] |  | defaults to undefined|


### Return type

**LeadImportIntoEDMV1Response**

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

