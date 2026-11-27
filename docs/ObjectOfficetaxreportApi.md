# ObjectOfficetaxreportApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**officetaxreportBatchDownloadV1**](#officetaxreportbatchdownloadv1) | **POST** /1/object/officetaxreport/{pkiOfficetaxreportID}/batchDownload | Download multiples attachments from an Officetaxreport|
|[**officetaxreportGetAttachmentsV1**](#officetaxreportgetattachmentsv1) | **GET** /1/object/officetaxreport/{pkiOfficetaxreportID}/getAttachments | Retrieve Officetaxreport\&#39;s attachments|
|[**officetaxreportGetCommunicationCountV1**](#officetaxreportgetcommunicationcountv1) | **GET** /1/object/officetaxreport/{pkiOfficetaxreportID}/getCommunicationCount | Retrieve Communication count|
|[**officetaxreportGetCommunicationListV1**](#officetaxreportgetcommunicationlistv1) | **GET** /1/object/officetaxreport/{pkiOfficetaxreportID}/getCommunicationList | Retrieve Communication list|
|[**officetaxreportGetCommunicationrecipientsV1**](#officetaxreportgetcommunicationrecipientsv1) | **GET** /1/object/officetaxreport/{pkiOfficetaxreportID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**officetaxreportGetCommunicationsendersV1**](#officetaxreportgetcommunicationsendersv1) | **GET** /1/object/officetaxreport/{pkiOfficetaxreportID}/getCommunicationsenders | Retrieve Communication senders|
|[**officetaxreportGetListV1**](#officetaxreportgetlistv1) | **GET** /1/object/officetaxreport/getList | Retrieve Officetaxreport list|
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

# **officetaxreportGetCommunicationCountV1**
> OfficetaxreportGetCommunicationCountV1Response officetaxreportGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let pkiOfficetaxreportID: number; // (default to undefined)

const { status, data } = await apiInstance.officetaxreportGetCommunicationCountV1(
    pkiOfficetaxreportID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOfficetaxreportID** | [**number**] |  | defaults to undefined|


### Return type

**OfficetaxreportGetCommunicationCountV1Response**

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

# **officetaxreportGetCommunicationListV1**
> OfficetaxreportGetCommunicationListV1Response officetaxreportGetCommunicationListV1()


### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let pkiOfficetaxreportID: number; // (default to undefined)

const { status, data } = await apiInstance.officetaxreportGetCommunicationListV1(
    pkiOfficetaxreportID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOfficetaxreportID** | [**number**] |  | defaults to undefined|


### Return type

**OfficetaxreportGetCommunicationListV1Response**

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

# **officetaxreportGetCommunicationrecipientsV1**
> OfficetaxreportGetCommunicationrecipientsV1Response officetaxreportGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let pkiOfficetaxreportID: number; // (default to undefined)

const { status, data } = await apiInstance.officetaxreportGetCommunicationrecipientsV1(
    pkiOfficetaxreportID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOfficetaxreportID** | [**number**] |  | defaults to undefined|


### Return type

**OfficetaxreportGetCommunicationrecipientsV1Response**

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

# **officetaxreportGetCommunicationsendersV1**
> OfficetaxreportGetCommunicationsendersV1Response officetaxreportGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let pkiOfficetaxreportID: number; // (default to undefined)

const { status, data } = await apiInstance.officetaxreportGetCommunicationsendersV1(
    pkiOfficetaxreportID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOfficetaxreportID** | [**number**] |  | defaults to undefined|


### Return type

**OfficetaxreportGetCommunicationsendersV1Response**

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

# **officetaxreportGetListV1**
> OfficetaxreportGetListV1Response officetaxreportGetListV1()



### Example

```typescript
import {
    ObjectOfficetaxreportApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOfficetaxreportApi(configuration);

let eOrderBy: 'pkiOfficetaxreportID_ASC' | 'pkiOfficetaxreportID_DESC' | 'fkiPeriodID_ASC' | 'fkiPeriodID_DESC' | 'sPeriodYYYYMM_ASC' | 'sPeriodYYYYMM_DESC' | 'sUserLoginname_ASC' | 'sUserLoginname_DESC' | 'dtCreatedDate_ASC' | 'dtCreatedDate_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.officetaxreportGetListV1(
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
| **eOrderBy** | [**&#39;pkiOfficetaxreportID_ASC&#39; | &#39;pkiOfficetaxreportID_DESC&#39; | &#39;fkiPeriodID_ASC&#39; | &#39;fkiPeriodID_DESC&#39; | &#39;sPeriodYYYYMM_ASC&#39; | &#39;sPeriodYYYYMM_DESC&#39; | &#39;sUserLoginname_ASC&#39; | &#39;sUserLoginname_DESC&#39; | &#39;dtCreatedDate_ASC&#39; | &#39;dtCreatedDate_DESC&#39;**]**Array<&#39;pkiOfficetaxreportID_ASC&#39; &#124; &#39;pkiOfficetaxreportID_DESC&#39; &#124; &#39;fkiPeriodID_ASC&#39; &#124; &#39;fkiPeriodID_DESC&#39; &#124; &#39;sPeriodYYYYMM_ASC&#39; &#124; &#39;sPeriodYYYYMM_DESC&#39; &#124; &#39;sUserLoginname_ASC&#39; &#124; &#39;sUserLoginname_DESC&#39; &#124; &#39;dtCreatedDate_ASC&#39; &#124; &#39;dtCreatedDate_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**OfficetaxreportGetListV1Response**

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

