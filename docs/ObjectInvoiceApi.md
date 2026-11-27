# ObjectInvoiceApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**invoiceBatchDownloadV1**](#invoicebatchdownloadv1) | **POST** /1/object/invoice/{pkiInvoiceID}/batchDownload | Download multiples attachments from an Invoice|
|[**invoiceGetAttachmentsV1**](#invoicegetattachmentsv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getAttachments | Retrieve Invoice\&#39;s Attachments|
|[**invoiceGetCommunicationCountV1**](#invoicegetcommunicationcountv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationCount | Retrieve Communication count|
|[**invoiceGetCommunicationListV1**](#invoicegetcommunicationlistv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationList | Retrieve Communication list|
|[**invoiceGetCommunicationrecipientsV1**](#invoicegetcommunicationrecipientsv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationrecipients | Retrieve Invoice\&#39;s Communicationrecipient|
|[**invoiceGetCommunicationsendersV1**](#invoicegetcommunicationsendersv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationsenders | Retrieve Invoice\&#39;s Communicationsender|
|[**invoiceGetDocumenttypechecklistV1**](#invoicegetdocumenttypechecklistv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getDocumenttypechecklist | Retrieve Document type checklist|
|[**invoiceGetListV1**](#invoicegetlistv1) | **GET** /1/object/invoice/getList | Retrieve Invoice list|
|[**invoiceImportIntoEDMV1**](#invoiceimportintoedmv1) | **POST** /1/object/invoice/{pkiInvoiceID}/importIntoEDM | Import attachments into the Invoice|
|[**invoiceSyncDocumenttypechecklistV1**](#invoicesyncdocumenttypechecklistv1) | **POST** /1/object/invoice/{pkiInvoiceID}/syncDocumenttypechecklist | Synchronize Document type checklist|

# **invoiceBatchDownloadV1**
> File invoiceBatchDownloadV1(invoiceBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration,
    InvoiceBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)
let invoiceBatchDownloadV1Request: InvoiceBatchDownloadV1Request; //

const { status, data } = await apiInstance.invoiceBatchDownloadV1(
    pkiInvoiceID,
    invoiceBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **invoiceBatchDownloadV1Request** | **InvoiceBatchDownloadV1Request**|  | |
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


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

# **invoiceGetAttachmentsV1**
> InvoiceGetAttachmentsV1Response invoiceGetAttachmentsV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetAttachmentsV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetAttachmentsV1Response**

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

# **invoiceGetCommunicationCountV1**
> InvoiceGetCommunicationCountV1Response invoiceGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationCountV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationCountV1Response**

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

# **invoiceGetCommunicationListV1**
> InvoiceGetCommunicationListV1Response invoiceGetCommunicationListV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationListV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationListV1Response**

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

# **invoiceGetCommunicationrecipientsV1**
> InvoiceGetCommunicationrecipientsV1Response invoiceGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationrecipientsV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationrecipientsV1Response**

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

# **invoiceGetCommunicationsendersV1**
> InvoiceGetCommunicationsendersV1Response invoiceGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationsendersV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationsendersV1Response**

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

# **invoiceGetDocumenttypechecklistV1**
> InvoiceGetDocumenttypechecklistV1Response invoiceGetDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetDocumenttypechecklistV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetDocumenttypechecklistV1Response**

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

# **invoiceGetListV1**
> InvoiceGetListV1Response invoiceGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eInvoiceType | Commission<br>CommissionAdvance<br>Financed<br>Manual<br>Monthly |

### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let eOrderBy: 'pkiInvoiceID_ASC' | 'pkiInvoiceID_DESC' | 'fkiAgentID_ASC' | 'fkiAgentID_DESC' | 'fkiBrokerID_ASC' | 'fkiBrokerID_DESC' | 'fkiCustomerID_ASC' | 'fkiCustomerID_DESC' | 'fkiPeriodID_ASC' | 'fkiPeriodID_DESC' | 'sPeriodYYYYMM_ASC' | 'sPeriodYYYYMM_DESC' | 'bInvoiceIspaid_ASC' | 'bInvoiceIspaid_DESC' | 'dInvoiceTotal_ASC' | 'dInvoiceTotal_DESC' | 'dInvoicePaid_ASC' | 'dInvoicePaid_DESC' | 'dInvoiceBalance_ASC' | 'dInvoiceBalance_DESC' | 'dtInvoiceDate_ASC' | 'dtInvoiceDate_DESC' | 'eInvoiceType_ASC' | 'eInvoiceType_DESC' | 'sInvoiceNumber_ASC' | 'sInvoiceNumber_DESC' | 'sInvoiceRecipient_ASC' | 'sInvoiceRecipient_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.invoiceGetListV1(
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
| **eOrderBy** | [**&#39;pkiInvoiceID_ASC&#39; | &#39;pkiInvoiceID_DESC&#39; | &#39;fkiAgentID_ASC&#39; | &#39;fkiAgentID_DESC&#39; | &#39;fkiBrokerID_ASC&#39; | &#39;fkiBrokerID_DESC&#39; | &#39;fkiCustomerID_ASC&#39; | &#39;fkiCustomerID_DESC&#39; | &#39;fkiPeriodID_ASC&#39; | &#39;fkiPeriodID_DESC&#39; | &#39;sPeriodYYYYMM_ASC&#39; | &#39;sPeriodYYYYMM_DESC&#39; | &#39;bInvoiceIspaid_ASC&#39; | &#39;bInvoiceIspaid_DESC&#39; | &#39;dInvoiceTotal_ASC&#39; | &#39;dInvoiceTotal_DESC&#39; | &#39;dInvoicePaid_ASC&#39; | &#39;dInvoicePaid_DESC&#39; | &#39;dInvoiceBalance_ASC&#39; | &#39;dInvoiceBalance_DESC&#39; | &#39;dtInvoiceDate_ASC&#39; | &#39;dtInvoiceDate_DESC&#39; | &#39;eInvoiceType_ASC&#39; | &#39;eInvoiceType_DESC&#39; | &#39;sInvoiceNumber_ASC&#39; | &#39;sInvoiceNumber_DESC&#39; | &#39;sInvoiceRecipient_ASC&#39; | &#39;sInvoiceRecipient_DESC&#39;**]**Array<&#39;pkiInvoiceID_ASC&#39; &#124; &#39;pkiInvoiceID_DESC&#39; &#124; &#39;fkiAgentID_ASC&#39; &#124; &#39;fkiAgentID_DESC&#39; &#124; &#39;fkiBrokerID_ASC&#39; &#124; &#39;fkiBrokerID_DESC&#39; &#124; &#39;fkiCustomerID_ASC&#39; &#124; &#39;fkiCustomerID_DESC&#39; &#124; &#39;fkiPeriodID_ASC&#39; &#124; &#39;fkiPeriodID_DESC&#39; &#124; &#39;sPeriodYYYYMM_ASC&#39; &#124; &#39;sPeriodYYYYMM_DESC&#39; &#124; &#39;bInvoiceIspaid_ASC&#39; &#124; &#39;bInvoiceIspaid_DESC&#39; &#124; &#39;dInvoiceTotal_ASC&#39; &#124; &#39;dInvoiceTotal_DESC&#39; &#124; &#39;dInvoicePaid_ASC&#39; &#124; &#39;dInvoicePaid_DESC&#39; &#124; &#39;dInvoiceBalance_ASC&#39; &#124; &#39;dInvoiceBalance_DESC&#39; &#124; &#39;dtInvoiceDate_ASC&#39; &#124; &#39;dtInvoiceDate_DESC&#39; &#124; &#39;eInvoiceType_ASC&#39; &#124; &#39;eInvoiceType_DESC&#39; &#124; &#39;sInvoiceNumber_ASC&#39; &#124; &#39;sInvoiceNumber_DESC&#39; &#124; &#39;sInvoiceRecipient_ASC&#39; &#124; &#39;sInvoiceRecipient_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**InvoiceGetListV1Response**

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

# **invoiceImportIntoEDMV1**
> InvoiceImportIntoEDMV1Response invoiceImportIntoEDMV1(invoiceImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration,
    InvoiceImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)
let invoiceImportIntoEDMV1Request: InvoiceImportIntoEDMV1Request; //

const { status, data } = await apiInstance.invoiceImportIntoEDMV1(
    pkiInvoiceID,
    invoiceImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **invoiceImportIntoEDMV1Request** | **InvoiceImportIntoEDMV1Request**|  | |
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceImportIntoEDMV1Response**

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

# **invoiceSyncDocumenttypechecklistV1**
> InvoiceSyncDocumenttypechecklistV1Response invoiceSyncDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)
let body: object; // (optional)

const { status, data } = await apiInstance.invoiceSyncDocumenttypechecklistV1(
    pkiInvoiceID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceSyncDocumenttypechecklistV1Response**

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

