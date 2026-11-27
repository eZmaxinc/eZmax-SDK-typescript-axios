# ObjectCommissionadvanceApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**commissionadvanceBatchDownloadV1**](#commissionadvancebatchdownloadv1) | **POST** /1/object/commissionadvance/{pkiCommissionadvanceID}/batchDownload | Download multiples attachments from a Commission advance|
|[**commissionadvanceGetAttachmentsV1**](#commissionadvancegetattachmentsv1) | **GET** /1/object/commissionadvance/{pkiCommissionadvanceID}/getAttachments | Retrieve Commissionadvance\&#39;s attachments|
|[**commissionadvanceGetCommunicationCountV1**](#commissionadvancegetcommunicationcountv1) | **GET** /1/object/commissionadvance/{pkiCommissionadvanceID}/getCommunicationCount | Retrieve Communication count|
|[**commissionadvanceGetCommunicationListV1**](#commissionadvancegetcommunicationlistv1) | **GET** /1/object/commissionadvance/{pkiCommissionadvanceID}/getCommunicationList | Retrieve Communication list|
|[**commissionadvanceGetCommunicationrecipientsV1**](#commissionadvancegetcommunicationrecipientsv1) | **GET** /1/object/commissionadvance/{pkiCommissionadvanceID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**commissionadvanceGetCommunicationsendersV1**](#commissionadvancegetcommunicationsendersv1) | **GET** /1/object/commissionadvance/{pkiCommissionadvanceID}/getCommunicationsenders | Retrieve Communication senders|
|[**commissionadvanceGetDocumenttypechecklistV1**](#commissionadvancegetdocumenttypechecklistv1) | **GET** /1/object/commissionadvance/{pkiCommissionadvanceID}/getDocumenttypechecklist | Retrieve Document type checklist|
|[**commissionadvanceImportIntoEDMV1**](#commissionadvanceimportintoedmv1) | **POST** /1/object/commissionadvance/{pkiCommissionadvanceID}/importIntoEDM | Import attachments into the Commissionadvance|
|[**commissionadvanceSyncDocumenttypechecklistV1**](#commissionadvancesyncdocumenttypechecklistv1) | **POST** /1/object/commissionadvance/{pkiCommissionadvanceID}/syncDocumenttypechecklist | Synchronize Document type checklist|

# **commissionadvanceBatchDownloadV1**
> File commissionadvanceBatchDownloadV1(commissionadvanceBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration,
    CommissionadvanceBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)
let commissionadvanceBatchDownloadV1Request: CommissionadvanceBatchDownloadV1Request; //

const { status, data } = await apiInstance.commissionadvanceBatchDownloadV1(
    pkiCommissionadvanceID,
    commissionadvanceBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **commissionadvanceBatchDownloadV1Request** | **CommissionadvanceBatchDownloadV1Request**|  | |
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


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

# **commissionadvanceGetAttachmentsV1**
> CommissionadvanceGetAttachmentsV1Response commissionadvanceGetAttachmentsV1()


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)

const { status, data } = await apiInstance.commissionadvanceGetAttachmentsV1(
    pkiCommissionadvanceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceGetAttachmentsV1Response**

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

# **commissionadvanceGetCommunicationCountV1**
> CommissionadvanceGetCommunicationCountV1Response commissionadvanceGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)

const { status, data } = await apiInstance.commissionadvanceGetCommunicationCountV1(
    pkiCommissionadvanceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceGetCommunicationCountV1Response**

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

# **commissionadvanceGetCommunicationListV1**
> CommissionadvanceGetCommunicationListV1Response commissionadvanceGetCommunicationListV1()


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)

const { status, data } = await apiInstance.commissionadvanceGetCommunicationListV1(
    pkiCommissionadvanceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceGetCommunicationListV1Response**

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

# **commissionadvanceGetCommunicationrecipientsV1**
> CommissionadvanceGetCommunicationrecipientsV1Response commissionadvanceGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)

const { status, data } = await apiInstance.commissionadvanceGetCommunicationrecipientsV1(
    pkiCommissionadvanceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceGetCommunicationrecipientsV1Response**

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

# **commissionadvanceGetCommunicationsendersV1**
> CommissionadvanceGetCommunicationsendersV1Response commissionadvanceGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)

const { status, data } = await apiInstance.commissionadvanceGetCommunicationsendersV1(
    pkiCommissionadvanceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceGetCommunicationsendersV1Response**

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

# **commissionadvanceGetDocumenttypechecklistV1**
> CommissionadvanceGetDocumenttypechecklistV1Response commissionadvanceGetDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)

const { status, data } = await apiInstance.commissionadvanceGetDocumenttypechecklistV1(
    pkiCommissionadvanceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceGetDocumenttypechecklistV1Response**

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

# **commissionadvanceImportIntoEDMV1**
> CommissionadvanceImportIntoEDMV1Response commissionadvanceImportIntoEDMV1(commissionadvanceImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration,
    CommissionadvanceImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)
let commissionadvanceImportIntoEDMV1Request: CommissionadvanceImportIntoEDMV1Request; //

const { status, data } = await apiInstance.commissionadvanceImportIntoEDMV1(
    pkiCommissionadvanceID,
    commissionadvanceImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **commissionadvanceImportIntoEDMV1Request** | **CommissionadvanceImportIntoEDMV1Request**|  | |
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceImportIntoEDMV1Response**

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

# **commissionadvanceSyncDocumenttypechecklistV1**
> CommissionadvanceSyncDocumenttypechecklistV1Response commissionadvanceSyncDocumenttypechecklistV1()


### Example

```typescript
import {
    ObjectCommissionadvanceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCommissionadvanceApi(configuration);

let pkiCommissionadvanceID: number; // (default to undefined)
let body: object; // (optional)

const { status, data } = await apiInstance.commissionadvanceSyncDocumenttypechecklistV1(
    pkiCommissionadvanceID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiCommissionadvanceID** | [**number**] |  | defaults to undefined|


### Return type

**CommissionadvanceSyncDocumenttypechecklistV1Response**

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

