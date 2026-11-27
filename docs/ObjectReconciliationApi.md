# ObjectReconciliationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**reconciliationBatchDownloadV1**](#reconciliationbatchdownloadv1) | **POST** /1/object/reconciliation/{pkiReconciliationID}/batchDownload | Download multiples attachments from a Reconciliation|
|[**reconciliationGetAttachmentsV1**](#reconciliationgetattachmentsv1) | **GET** /1/object/reconciliation/{pkiReconciliationID}/getAttachments | Retrieve Reconciliation\&#39;s attachments|
|[**reconciliationGetCommunicationCountV1**](#reconciliationgetcommunicationcountv1) | **GET** /1/object/reconciliation/{pkiReconciliationID}/getCommunicationCount | Retrieve Communication count|
|[**reconciliationGetCommunicationListV1**](#reconciliationgetcommunicationlistv1) | **GET** /1/object/reconciliation/{pkiReconciliationID}/getCommunicationList | Retrieve Communication list|
|[**reconciliationGetCommunicationrecipientsV1**](#reconciliationgetcommunicationrecipientsv1) | **GET** /1/object/reconciliation/{pkiReconciliationID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**reconciliationGetCommunicationsendersV1**](#reconciliationgetcommunicationsendersv1) | **GET** /1/object/reconciliation/{pkiReconciliationID}/getCommunicationsenders | Retrieve Communication senders|
|[**reconciliationGetDocumenttypechecklistV1**](#reconciliationgetdocumenttypechecklistv1) | **GET** /1/object/reconciliation/{pkiReconciliationID}/getDocumenttypechecklist | Retrieve Document type checklist|
|[**reconciliationImportIntoEDMV1**](#reconciliationimportintoedmv1) | **POST** /1/object/reconciliation/{pkiReconciliationID}/importIntoEDM | Import attachments into the Reconciliation|
|[**reconciliationSyncDocumenttypechecklistV1**](#reconciliationsyncdocumenttypechecklistv1) | **POST** /1/object/reconciliation/{pkiReconciliationID}/syncDocumenttypechecklist | Synchronize Document type checklist|

# **reconciliationBatchDownloadV1**
> File reconciliationBatchDownloadV1(reconciliationBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration,
    ReconciliationBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)
let reconciliationBatchDownloadV1Request: ReconciliationBatchDownloadV1Request; //

const { status, data } = await apiInstance.reconciliationBatchDownloadV1(
    pkiReconciliationID,
    reconciliationBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **reconciliationBatchDownloadV1Request** | **ReconciliationBatchDownloadV1Request**|  | |
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


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

# **reconciliationGetAttachmentsV1**
> ReconciliationGetAttachmentsV1Response reconciliationGetAttachmentsV1()


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)

const { status, data } = await apiInstance.reconciliationGetAttachmentsV1(
    pkiReconciliationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationGetAttachmentsV1Response**

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

# **reconciliationGetCommunicationCountV1**
> ReconciliationGetCommunicationCountV1Response reconciliationGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)

const { status, data } = await apiInstance.reconciliationGetCommunicationCountV1(
    pkiReconciliationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationGetCommunicationCountV1Response**

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

# **reconciliationGetCommunicationListV1**
> ReconciliationGetCommunicationListV1Response reconciliationGetCommunicationListV1()


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)

const { status, data } = await apiInstance.reconciliationGetCommunicationListV1(
    pkiReconciliationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationGetCommunicationListV1Response**

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

# **reconciliationGetCommunicationrecipientsV1**
> ReconciliationGetCommunicationrecipientsV1Response reconciliationGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)

const { status, data } = await apiInstance.reconciliationGetCommunicationrecipientsV1(
    pkiReconciliationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationGetCommunicationrecipientsV1Response**

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

# **reconciliationGetCommunicationsendersV1**
> ReconciliationGetCommunicationsendersV1Response reconciliationGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)

const { status, data } = await apiInstance.reconciliationGetCommunicationsendersV1(
    pkiReconciliationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationGetCommunicationsendersV1Response**

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

# **reconciliationGetDocumenttypechecklistV1**
> ReconciliationGetDocumenttypechecklistV1Response reconciliationGetDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)

const { status, data } = await apiInstance.reconciliationGetDocumenttypechecklistV1(
    pkiReconciliationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationGetDocumenttypechecklistV1Response**

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

# **reconciliationImportIntoEDMV1**
> ReconciliationImportIntoEDMV1Response reconciliationImportIntoEDMV1(reconciliationImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration,
    ReconciliationImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)
let reconciliationImportIntoEDMV1Request: ReconciliationImportIntoEDMV1Request; //

const { status, data } = await apiInstance.reconciliationImportIntoEDMV1(
    pkiReconciliationID,
    reconciliationImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **reconciliationImportIntoEDMV1Request** | **ReconciliationImportIntoEDMV1Request**|  | |
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationImportIntoEDMV1Response**

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

# **reconciliationSyncDocumenttypechecklistV1**
> ReconciliationSyncDocumenttypechecklistV1Response reconciliationSyncDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectReconciliationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectReconciliationApi(configuration);

let pkiReconciliationID: number; // (default to undefined)
let body: object; // (optional)

const { status, data } = await apiInstance.reconciliationSyncDocumenttypechecklistV1(
    pkiReconciliationID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiReconciliationID** | [**number**] |  | defaults to undefined|


### Return type

**ReconciliationSyncDocumenttypechecklistV1Response**

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

