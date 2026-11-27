# ObjectSalaryApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**salaryBatchDownloadV1**](#salarybatchdownloadv1) | **POST** /1/object/salary/{pkiSalaryID}/batchDownload | Download multiples attachments from a Reconciliation|
|[**salaryGetAttachmentsV1**](#salarygetattachmentsv1) | **GET** /1/object/salary/{pkiSalaryID}/getAttachments | Retrieve Salary\&#39;s attachments|
|[**salaryGetCommunicationCountV1**](#salarygetcommunicationcountv1) | **GET** /1/object/salary/{pkiSalaryID}/getCommunicationCount | Retrieve Communication count|
|[**salaryGetCommunicationListV1**](#salarygetcommunicationlistv1) | **GET** /1/object/salary/{pkiSalaryID}/getCommunicationList | Retrieve Communication list|
|[**salaryGetCommunicationrecipientsV1**](#salarygetcommunicationrecipientsv1) | **GET** /1/object/salary/{pkiSalaryID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**salaryGetCommunicationsendersV1**](#salarygetcommunicationsendersv1) | **GET** /1/object/salary/{pkiSalaryID}/getCommunicationsenders | Retrieve Communication senders|
|[**salaryGetListV1**](#salarygetlistv1) | **GET** /1/object/salary/getList | Retrieve Salary list|
|[**salaryImportIntoEDMV1**](#salaryimportintoedmv1) | **POST** /1/object/salary/{pkiSalaryID}/importIntoEDM | Import attachments into the Salary|

# **salaryBatchDownloadV1**
> File salaryBatchDownloadV1(salaryBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration,
    SalaryBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let pkiSalaryID: number; // (default to undefined)
let salaryBatchDownloadV1Request: SalaryBatchDownloadV1Request; //

const { status, data } = await apiInstance.salaryBatchDownloadV1(
    pkiSalaryID,
    salaryBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **salaryBatchDownloadV1Request** | **SalaryBatchDownloadV1Request**|  | |
| **pkiSalaryID** | [**number**] |  | defaults to undefined|


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

# **salaryGetAttachmentsV1**
> SalaryGetAttachmentsV1Response salaryGetAttachmentsV1()


### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let pkiSalaryID: number; // (default to undefined)

const { status, data } = await apiInstance.salaryGetAttachmentsV1(
    pkiSalaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSalaryID** | [**number**] |  | defaults to undefined|


### Return type

**SalaryGetAttachmentsV1Response**

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

# **salaryGetCommunicationCountV1**
> SalaryGetCommunicationCountV1Response salaryGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let pkiSalaryID: number; // (default to undefined)

const { status, data } = await apiInstance.salaryGetCommunicationCountV1(
    pkiSalaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSalaryID** | [**number**] |  | defaults to undefined|


### Return type

**SalaryGetCommunicationCountV1Response**

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

# **salaryGetCommunicationListV1**
> SalaryGetCommunicationListV1Response salaryGetCommunicationListV1()


### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let pkiSalaryID: number; // (default to undefined)

const { status, data } = await apiInstance.salaryGetCommunicationListV1(
    pkiSalaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSalaryID** | [**number**] |  | defaults to undefined|


### Return type

**SalaryGetCommunicationListV1Response**

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

# **salaryGetCommunicationrecipientsV1**
> SalaryGetCommunicationrecipientsV1Response salaryGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let pkiSalaryID: number; // (default to undefined)

const { status, data } = await apiInstance.salaryGetCommunicationrecipientsV1(
    pkiSalaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSalaryID** | [**number**] |  | defaults to undefined|


### Return type

**SalaryGetCommunicationrecipientsV1Response**

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

# **salaryGetCommunicationsendersV1**
> SalaryGetCommunicationsendersV1Response salaryGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let pkiSalaryID: number; // (default to undefined)

const { status, data } = await apiInstance.salaryGetCommunicationsendersV1(
    pkiSalaryID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSalaryID** | [**number**] |  | defaults to undefined|


### Return type

**SalaryGetCommunicationsendersV1Response**

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

# **salaryGetListV1**
> SalaryGetListV1Response salaryGetListV1()



### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let eOrderBy: 'pkiSalaryID_ASC' | 'pkiSalaryID_DESC' | 'fkiPeriodID_ASC' | 'fkiPeriodID_DESC' | 'fkiUSerIDCreated_ASC' | 'fkiUSerIDCreated_DESC' | 'fkiSalaryperiodID_ASC' | 'fkiSalaryperiodID_DESC' | 'dtSalaryPaymentdate_ASC' | 'dtSalaryPaymentdate_DESC' | 'sSalaryperiod_ASC' | 'sSalaryperiod_DESC' | 'sPeriodYYYYMM_ASC' | 'sPeriodYYYYMM_DESC' | 'iSalarypreparationCount_ASC' | 'iSalarypreparationCount_DESC' | 'dSalarypreparationTotal_ASC' | 'dSalarypreparationTotal_DESC' | 'dtSalaryperiodStart_ASC' | 'dtSalaryperiodStart_DESC' | 'dtSalaryperiodEnd_ASC' | 'dtSalaryperiodEnd_DESC' | 'sUserLoginname_ASC' | 'sUserLoginname_DESC' | 'dtCreatedDate_ASC' | 'dtCreatedDate_DESC' | 'bSalarypreparationIspaid_ASC' | 'bSalarypreparationIspaid_DESC' | 'iSalaryperiodgroupYear_ASC' | 'iSalaryperiodgroupYear_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.salaryGetListV1(
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
| **eOrderBy** | [**&#39;pkiSalaryID_ASC&#39; | &#39;pkiSalaryID_DESC&#39; | &#39;fkiPeriodID_ASC&#39; | &#39;fkiPeriodID_DESC&#39; | &#39;fkiUSerIDCreated_ASC&#39; | &#39;fkiUSerIDCreated_DESC&#39; | &#39;fkiSalaryperiodID_ASC&#39; | &#39;fkiSalaryperiodID_DESC&#39; | &#39;dtSalaryPaymentdate_ASC&#39; | &#39;dtSalaryPaymentdate_DESC&#39; | &#39;sSalaryperiod_ASC&#39; | &#39;sSalaryperiod_DESC&#39; | &#39;sPeriodYYYYMM_ASC&#39; | &#39;sPeriodYYYYMM_DESC&#39; | &#39;iSalarypreparationCount_ASC&#39; | &#39;iSalarypreparationCount_DESC&#39; | &#39;dSalarypreparationTotal_ASC&#39; | &#39;dSalarypreparationTotal_DESC&#39; | &#39;dtSalaryperiodStart_ASC&#39; | &#39;dtSalaryperiodStart_DESC&#39; | &#39;dtSalaryperiodEnd_ASC&#39; | &#39;dtSalaryperiodEnd_DESC&#39; | &#39;sUserLoginname_ASC&#39; | &#39;sUserLoginname_DESC&#39; | &#39;dtCreatedDate_ASC&#39; | &#39;dtCreatedDate_DESC&#39; | &#39;bSalarypreparationIspaid_ASC&#39; | &#39;bSalarypreparationIspaid_DESC&#39; | &#39;iSalaryperiodgroupYear_ASC&#39; | &#39;iSalaryperiodgroupYear_DESC&#39;**]**Array<&#39;pkiSalaryID_ASC&#39; &#124; &#39;pkiSalaryID_DESC&#39; &#124; &#39;fkiPeriodID_ASC&#39; &#124; &#39;fkiPeriodID_DESC&#39; &#124; &#39;fkiUSerIDCreated_ASC&#39; &#124; &#39;fkiUSerIDCreated_DESC&#39; &#124; &#39;fkiSalaryperiodID_ASC&#39; &#124; &#39;fkiSalaryperiodID_DESC&#39; &#124; &#39;dtSalaryPaymentdate_ASC&#39; &#124; &#39;dtSalaryPaymentdate_DESC&#39; &#124; &#39;sSalaryperiod_ASC&#39; &#124; &#39;sSalaryperiod_DESC&#39; &#124; &#39;sPeriodYYYYMM_ASC&#39; &#124; &#39;sPeriodYYYYMM_DESC&#39; &#124; &#39;iSalarypreparationCount_ASC&#39; &#124; &#39;iSalarypreparationCount_DESC&#39; &#124; &#39;dSalarypreparationTotal_ASC&#39; &#124; &#39;dSalarypreparationTotal_DESC&#39; &#124; &#39;dtSalaryperiodStart_ASC&#39; &#124; &#39;dtSalaryperiodStart_DESC&#39; &#124; &#39;dtSalaryperiodEnd_ASC&#39; &#124; &#39;dtSalaryperiodEnd_DESC&#39; &#124; &#39;sUserLoginname_ASC&#39; &#124; &#39;sUserLoginname_DESC&#39; &#124; &#39;dtCreatedDate_ASC&#39; &#124; &#39;dtCreatedDate_DESC&#39; &#124; &#39;bSalarypreparationIspaid_ASC&#39; &#124; &#39;bSalarypreparationIspaid_DESC&#39; &#124; &#39;iSalaryperiodgroupYear_ASC&#39; &#124; &#39;iSalaryperiodgroupYear_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**SalaryGetListV1Response**

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

# **salaryImportIntoEDMV1**
> SalaryImportIntoEDMV1Response salaryImportIntoEDMV1(salaryImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectSalaryApi,
    Configuration,
    SalaryImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSalaryApi(configuration);

let pkiSalaryID: number; // (default to undefined)
let salaryImportIntoEDMV1Request: SalaryImportIntoEDMV1Request; //

const { status, data } = await apiInstance.salaryImportIntoEDMV1(
    pkiSalaryID,
    salaryImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **salaryImportIntoEDMV1Request** | **SalaryImportIntoEDMV1Request**|  | |
| **pkiSalaryID** | [**number**] |  | defaults to undefined|


### Return type

**SalaryImportIntoEDMV1Response**

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

