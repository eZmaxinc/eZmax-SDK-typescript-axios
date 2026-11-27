# ObjectDeposittransitchequeApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**deposittransitchequeBatchDownloadV1**](#deposittransitchequebatchdownloadv1) | **POST** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/batchDownload | Download multiples attachments from a Deposittransitcheque|
|[**deposittransitchequeGetAttachmentsV1**](#deposittransitchequegetattachmentsv1) | **GET** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/getAttachments | Retrieve Deposittransitcheque\&#39;s attachments|
|[**deposittransitchequeGetCommunicationCountV1**](#deposittransitchequegetcommunicationcountv1) | **GET** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/getCommunicationCount | Retrieve Communication count|
|[**deposittransitchequeGetCommunicationListV1**](#deposittransitchequegetcommunicationlistv1) | **GET** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/getCommunicationList | Retrieve Communication list|
|[**deposittransitchequeGetCommunicationrecipientsV1**](#deposittransitchequegetcommunicationrecipientsv1) | **GET** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**deposittransitchequeGetCommunicationsendersV1**](#deposittransitchequegetcommunicationsendersv1) | **GET** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/getCommunicationsenders | Retrieve Communication senders|
|[**deposittransitchequeGetDocumenttypechecklistV1**](#deposittransitchequegetdocumenttypechecklistv1) | **GET** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/getDocumenttypechecklist | Retrieve Document type checklist|
|[**deposittransitchequeGetListV1**](#deposittransitchequegetlistv1) | **GET** /1/object/deposittransitcheque/getList | Retrieve Deposittransitcheque list|
|[**deposittransitchequeImportIntoEDMV1**](#deposittransitchequeimportintoedmv1) | **POST** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/importIntoEDM | Import attachments into the Deposittransitcheque|
|[**deposittransitchequeSyncDocumenttypechecklistV1**](#deposittransitchequesyncdocumenttypechecklistv1) | **POST** /1/object/deposittransitcheque/{pkiDeposittransitchequeID}/syncDocumenttypechecklist | Synchronize Document type checklist|

# **deposittransitchequeBatchDownloadV1**
> File deposittransitchequeBatchDownloadV1(deposittransitchequeBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration,
    DeposittransitchequeBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)
let deposittransitchequeBatchDownloadV1Request: DeposittransitchequeBatchDownloadV1Request; //

const { status, data } = await apiInstance.deposittransitchequeBatchDownloadV1(
    pkiDeposittransitchequeID,
    deposittransitchequeBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **deposittransitchequeBatchDownloadV1Request** | **DeposittransitchequeBatchDownloadV1Request**|  | |
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


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

# **deposittransitchequeGetAttachmentsV1**
> DeposittransitchequeGetAttachmentsV1Response deposittransitchequeGetAttachmentsV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetAttachmentsV1(
    pkiDeposittransitchequeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeGetAttachmentsV1Response**

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

# **deposittransitchequeGetCommunicationCountV1**
> DeposittransitchequeGetCommunicationCountV1Response deposittransitchequeGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetCommunicationCountV1(
    pkiDeposittransitchequeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeGetCommunicationCountV1Response**

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

# **deposittransitchequeGetCommunicationListV1**
> DeposittransitchequeGetCommunicationListV1Response deposittransitchequeGetCommunicationListV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetCommunicationListV1(
    pkiDeposittransitchequeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeGetCommunicationListV1Response**

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

# **deposittransitchequeGetCommunicationrecipientsV1**
> DeposittransitchequeGetCommunicationrecipientsV1Response deposittransitchequeGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetCommunicationrecipientsV1(
    pkiDeposittransitchequeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeGetCommunicationrecipientsV1Response**

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

# **deposittransitchequeGetCommunicationsendersV1**
> DeposittransitchequeGetCommunicationsendersV1Response deposittransitchequeGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetCommunicationsendersV1(
    pkiDeposittransitchequeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeGetCommunicationsendersV1Response**

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

# **deposittransitchequeGetDocumenttypechecklistV1**
> DeposittransitchequeGetDocumenttypechecklistV1Response deposittransitchequeGetDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetDocumenttypechecklistV1(
    pkiDeposittransitchequeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeGetDocumenttypechecklistV1Response**

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

# **deposittransitchequeGetListV1**
> DeposittransitchequeGetListV1Response deposittransitchequeGetListV1()



### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let eOrderBy: 'pkiDeposittransitchequeID_ASC' | 'pkiDeposittransitchequeID_DESC' | 'fkiBankaccountID_ASC' | 'fkiBankaccountID_DESC' | 'fkiDepositID_ASC' | 'fkiDepositID_DESC' | 'sDeposittransitchequeNumber_ASC' | 'sDeposittransitchequeNumber_DESC' | 'dtDeposittransitchequeDate_ASC' | 'dtDeposittransitchequeDate_DESC' | 'dDeposittransitchequeAmount_ASC' | 'dDeposittransitchequeAmount_DESC' | 'sBankaccountBankname_ASC' | 'sBankaccountBankname_DESC' | 'sPeriodYYYYMM_ASC' | 'sPeriodYYYYMM_DESC' | 'sCustomerName_ASC' | 'sCustomerName_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.deposittransitchequeGetListV1(
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
| **eOrderBy** | [**&#39;pkiDeposittransitchequeID_ASC&#39; | &#39;pkiDeposittransitchequeID_DESC&#39; | &#39;fkiBankaccountID_ASC&#39; | &#39;fkiBankaccountID_DESC&#39; | &#39;fkiDepositID_ASC&#39; | &#39;fkiDepositID_DESC&#39; | &#39;sDeposittransitchequeNumber_ASC&#39; | &#39;sDeposittransitchequeNumber_DESC&#39; | &#39;dtDeposittransitchequeDate_ASC&#39; | &#39;dtDeposittransitchequeDate_DESC&#39; | &#39;dDeposittransitchequeAmount_ASC&#39; | &#39;dDeposittransitchequeAmount_DESC&#39; | &#39;sBankaccountBankname_ASC&#39; | &#39;sBankaccountBankname_DESC&#39; | &#39;sPeriodYYYYMM_ASC&#39; | &#39;sPeriodYYYYMM_DESC&#39; | &#39;sCustomerName_ASC&#39; | &#39;sCustomerName_DESC&#39;**]**Array<&#39;pkiDeposittransitchequeID_ASC&#39; &#124; &#39;pkiDeposittransitchequeID_DESC&#39; &#124; &#39;fkiBankaccountID_ASC&#39; &#124; &#39;fkiBankaccountID_DESC&#39; &#124; &#39;fkiDepositID_ASC&#39; &#124; &#39;fkiDepositID_DESC&#39; &#124; &#39;sDeposittransitchequeNumber_ASC&#39; &#124; &#39;sDeposittransitchequeNumber_DESC&#39; &#124; &#39;dtDeposittransitchequeDate_ASC&#39; &#124; &#39;dtDeposittransitchequeDate_DESC&#39; &#124; &#39;dDeposittransitchequeAmount_ASC&#39; &#124; &#39;dDeposittransitchequeAmount_DESC&#39; &#124; &#39;sBankaccountBankname_ASC&#39; &#124; &#39;sBankaccountBankname_DESC&#39; &#124; &#39;sPeriodYYYYMM_ASC&#39; &#124; &#39;sPeriodYYYYMM_DESC&#39; &#124; &#39;sCustomerName_ASC&#39; &#124; &#39;sCustomerName_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**DeposittransitchequeGetListV1Response**

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

# **deposittransitchequeImportIntoEDMV1**
> DeposittransitchequeImportIntoEDMV1Response deposittransitchequeImportIntoEDMV1(deposittransitchequeImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration,
    DeposittransitchequeImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)
let deposittransitchequeImportIntoEDMV1Request: DeposittransitchequeImportIntoEDMV1Request; //

const { status, data } = await apiInstance.deposittransitchequeImportIntoEDMV1(
    pkiDeposittransitchequeID,
    deposittransitchequeImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **deposittransitchequeImportIntoEDMV1Request** | **DeposittransitchequeImportIntoEDMV1Request**|  | |
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeImportIntoEDMV1Response**

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

# **deposittransitchequeSyncDocumenttypechecklistV1**
> DeposittransitchequeSyncDocumenttypechecklistV1Response deposittransitchequeSyncDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectDeposittransitchequeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDeposittransitchequeApi(configuration);

let pkiDeposittransitchequeID: number; // (default to undefined)
let body: object; // (optional)

const { status, data } = await apiInstance.deposittransitchequeSyncDocumenttypechecklistV1(
    pkiDeposittransitchequeID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiDeposittransitchequeID** | [**number**] |  | defaults to undefined|


### Return type

**DeposittransitchequeSyncDocumenttypechecklistV1Response**

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

