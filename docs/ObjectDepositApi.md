# ObjectDepositApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**depositBatchDownloadV1**](#depositbatchdownloadv1) | **POST** /1/object/deposit/{pkiDepositID}/batchDownload | Download multiples attachments from a Deposit|
|[**depositGetAttachmentsV1**](#depositgetattachmentsv1) | **GET** /1/object/deposit/{pkiDepositID}/getAttachments | Retrieve Deposit\&#39;s attachments|
|[**depositGetCommunicationCountV1**](#depositgetcommunicationcountv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationCount | Retrieve Communication count|
|[**depositGetCommunicationListV1**](#depositgetcommunicationlistv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationList | Retrieve Communication list|
|[**depositGetCommunicationrecipientsV1**](#depositgetcommunicationrecipientsv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**depositGetCommunicationsendersV1**](#depositgetcommunicationsendersv1) | **GET** /1/object/deposit/{pkiDepositID}/getCommunicationsenders | Retrieve Communication senders|
|[**depositGetListV1**](#depositgetlistv1) | **GET** /1/object/deposit/getList | Retrieve Deposit list|
|[**depositImportIntoEDMV1**](#depositimportintoedmv1) | **POST** /1/object/deposit/{pkiDepositID}/importIntoEDM | Import attachments into the Deposit|

# **depositBatchDownloadV1**
> File depositBatchDownloadV1(depositBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration,
    DepositBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)
let depositBatchDownloadV1Request: DepositBatchDownloadV1Request; //

const { status, data } = await apiInstance.depositBatchDownloadV1(
    pkiDepositID,
    depositBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **depositBatchDownloadV1Request** | **DepositBatchDownloadV1Request**|  | |
| **pkiDepositID** | [**number**] |  | defaults to undefined|


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

# **depositGetAttachmentsV1**
> DepositGetAttachmentsV1Response depositGetAttachmentsV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetAttachmentsV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetAttachmentsV1Response**

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

# **depositGetCommunicationCountV1**
> DepositGetCommunicationCountV1Response depositGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationCountV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationCountV1Response**

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

# **depositGetCommunicationListV1**
> DepositGetCommunicationListV1Response depositGetCommunicationListV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationListV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationListV1Response**

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

# **depositGetCommunicationrecipientsV1**
> DepositGetCommunicationrecipientsV1Response depositGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationrecipientsV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationrecipientsV1Response**

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

# **depositGetCommunicationsendersV1**
> DepositGetCommunicationsendersV1Response depositGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)

const { status, data } = await apiInstance.depositGetCommunicationsendersV1(
    pkiDepositID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositGetCommunicationsendersV1Response**

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

# **depositGetListV1**
> DepositGetListV1Response depositGetListV1()



### Example

```typescript
import {
    ObjectDepositApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let eOrderBy: 'pkiDepositID_ASC' | 'pkiDepositID_DESC' | 'fkiPeriodID_ASC' | 'fkiPeriodID_DESC' | 'fkiBankaccountID_ASC' | 'fkiBankaccountID_DESC' | 'fkiUserIDCreated_ASC' | 'fkiUserIDCreated_DESC' | 'sDepositNumber_ASC' | 'sDepositNumber_DESC' | 'dtDepositDate_ASC' | 'dtDepositDate_DESC' | 'dDepositTotal_ASC' | 'dDepositTotal_DESC' | 'dtCreatedDate_ASC' | 'dtCreatedDate_DESC' | 'bDepositDraft_ASC' | 'bDepositDraft_DESC' | 'bDepositReconciled_ASC' | 'bDepositReconciled_DESC' | 'fkiReconciliationID_ASC' | 'fkiReconciliationID_DESC' | 'sBankaccountBankname_ASC' | 'sBankaccountBankname_DESC' | 'sPeriodYYYYMM_ASC' | 'sPeriodYYYYMM_DESC' | 'sUserLoginname_ASC' | 'sUserLoginname_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.depositGetListV1(
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
| **eOrderBy** | [**&#39;pkiDepositID_ASC&#39; | &#39;pkiDepositID_DESC&#39; | &#39;fkiPeriodID_ASC&#39; | &#39;fkiPeriodID_DESC&#39; | &#39;fkiBankaccountID_ASC&#39; | &#39;fkiBankaccountID_DESC&#39; | &#39;fkiUserIDCreated_ASC&#39; | &#39;fkiUserIDCreated_DESC&#39; | &#39;sDepositNumber_ASC&#39; | &#39;sDepositNumber_DESC&#39; | &#39;dtDepositDate_ASC&#39; | &#39;dtDepositDate_DESC&#39; | &#39;dDepositTotal_ASC&#39; | &#39;dDepositTotal_DESC&#39; | &#39;dtCreatedDate_ASC&#39; | &#39;dtCreatedDate_DESC&#39; | &#39;bDepositDraft_ASC&#39; | &#39;bDepositDraft_DESC&#39; | &#39;bDepositReconciled_ASC&#39; | &#39;bDepositReconciled_DESC&#39; | &#39;fkiReconciliationID_ASC&#39; | &#39;fkiReconciliationID_DESC&#39; | &#39;sBankaccountBankname_ASC&#39; | &#39;sBankaccountBankname_DESC&#39; | &#39;sPeriodYYYYMM_ASC&#39; | &#39;sPeriodYYYYMM_DESC&#39; | &#39;sUserLoginname_ASC&#39; | &#39;sUserLoginname_DESC&#39;**]**Array<&#39;pkiDepositID_ASC&#39; &#124; &#39;pkiDepositID_DESC&#39; &#124; &#39;fkiPeriodID_ASC&#39; &#124; &#39;fkiPeriodID_DESC&#39; &#124; &#39;fkiBankaccountID_ASC&#39; &#124; &#39;fkiBankaccountID_DESC&#39; &#124; &#39;fkiUserIDCreated_ASC&#39; &#124; &#39;fkiUserIDCreated_DESC&#39; &#124; &#39;sDepositNumber_ASC&#39; &#124; &#39;sDepositNumber_DESC&#39; &#124; &#39;dtDepositDate_ASC&#39; &#124; &#39;dtDepositDate_DESC&#39; &#124; &#39;dDepositTotal_ASC&#39; &#124; &#39;dDepositTotal_DESC&#39; &#124; &#39;dtCreatedDate_ASC&#39; &#124; &#39;dtCreatedDate_DESC&#39; &#124; &#39;bDepositDraft_ASC&#39; &#124; &#39;bDepositDraft_DESC&#39; &#124; &#39;bDepositReconciled_ASC&#39; &#124; &#39;bDepositReconciled_DESC&#39; &#124; &#39;fkiReconciliationID_ASC&#39; &#124; &#39;fkiReconciliationID_DESC&#39; &#124; &#39;sBankaccountBankname_ASC&#39; &#124; &#39;sBankaccountBankname_DESC&#39; &#124; &#39;sPeriodYYYYMM_ASC&#39; &#124; &#39;sPeriodYYYYMM_DESC&#39; &#124; &#39;sUserLoginname_ASC&#39; &#124; &#39;sUserLoginname_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**DepositGetListV1Response**

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

# **depositImportIntoEDMV1**
> DepositImportIntoEDMV1Response depositImportIntoEDMV1(depositImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectDepositApi,
    Configuration,
    DepositImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDepositApi(configuration);

let pkiDepositID: number; // (default to undefined)
let depositImportIntoEDMV1Request: DepositImportIntoEDMV1Request; //

const { status, data } = await apiInstance.depositImportIntoEDMV1(
    pkiDepositID,
    depositImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **depositImportIntoEDMV1Request** | **DepositImportIntoEDMV1Request**|  | |
| **pkiDepositID** | [**number**] |  | defaults to undefined|


### Return type

**DepositImportIntoEDMV1Response**

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

